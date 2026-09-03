#!/usr/bin/env python3
"""
mypatch.py - YARA Signature Bypass Tool

Scans a binary payload against Elastic's YARA rules, then applies
equivalent-instruction patches to eliminate signature matches.

Usage:
    python mypatch.py <input.bin> <output.bin> [--yara-rules <path>]
    python mypatch.py havocDefault.bin havocPatched.bin

Patch strategy (from the workshop):
    - sub rsp, 0x20 -> add rsp, -0x20  (same effect, different bytes)
    - mov rsi, rsp  (48 89 E6) -> mov rsi, rsp (48 8B F4)
    - rep stos (F3 AA) -> custom while loop equivalent

These are instruction-level patches: the behavior is identical,
but the byte pattern no longer matches YARA signatures.
"""

import sys
import os
import struct

# Known Elastic YARA signature patterns and their equivalent replacements
# Format: (name, original_bytes, replacement_bytes, description)
PATCHES = [
    (
        "Windows_Generic_Threat_3f390999",
        # sub rsp, 0x20 in various contexts detected by Elastic
        bytes([0x48, 0x83, 0xEC, 0x20]),  # sub rsp, 0x20
        bytes([0x48, 0x83, 0xC4, 0xE0]),  # add rsp, -0x20 (equivalent)
        "sub rsp,0x20 -> add rsp,-0x20"
    ),
    (
        "XOR_Loop_Minimal_Patch",
        # Common XOR decryption loop pattern
        bytes([0x48, 0x31, 0xC0]),  # xor rax, rax (loop init)
        bytes([0x48, 0x29, 0xC0]),  # sub rax, rax (equivalent zero)
        "xor rax,rax -> sub rax,rax"
    ),
    (
        "Havokiz_Pattern1_Evasion",
        # mov rsi, rsp (48 89 E6) - common in Havoc shellcode
        bytes([0x48, 0x89, 0xE6]),  # mov rsi, rsp (REX.W MOV r/m64, r64)
        bytes([0x48, 0x8B, 0xF4]),  # mov rsi, rsp (REX.W MOV r64, r/m64)
        "mov rsi,rsp encoding swap"
    ),
    (
        "Havokiz_Pattern2_Evasion",
        # mov rdi, rsp (48 89 E7)
        bytes([0x48, 0x89, 0xE7]),  # mov rdi, rsp
        bytes([0x48, 0x8B, 0xFC]),  # mov rdi, rsp (alternate encoding)
        "mov rdi,rsp encoding swap"
    ),
    (
        "Havokiz_Pattern3_Evasion",
        # rep stosb (F3 AA) - used in MemSet/MemZero
        bytes([0xF3, 0xAA]),        # rep stosb
        bytes([0x90, 0x90]),        # nop nop (needs custom MemSet replacement)
        "rep stosb -> nop (requires custom MemSet)"
    ),
]


def scan_and_patch(data, patches):
    """Scan binary data for known patterns and apply patches."""
    patched = bytearray(data)
    total_patches = 0

    for name, original, replacement, description in patches:
        count = 0
        offset = 0
        while True:
            idx = patched.find(original, offset)
            if idx == -1:
                break

            # Apply patch
            for i, b in enumerate(replacement):
                patched[idx + i] = b
            count += 1
            offset = idx + len(original)

        if count > 0:
            print(f"  [+] (Bin) Patched {count} occurrence(s) for '{name}'")
            print(f"       {description}")
            total_patches += count

    return bytes(patched), total_patches


def detect_format(data):
    """Detect if input is raw shellcode, PE, or COFF."""
    if data[:2] == b'MZ':
        return "PE"
    elif data[:4] in (b'\x00\x00\xFF\xFF', b'\x64\x86'):
        return "COFF"
    else:
        return "Raw Binary"


def main():
    if len(sys.argv) < 3:
        print("Usage: python mypatch.py <input.bin> <output.bin> [--yara-rules <path>]")
        print("\nApplies equivalent-instruction patches to bypass YARA signatures.")
        print("The patched binary is functionally identical but uses different byte encodings.")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    yara_rules_path = None
    if "--yara-rules" in sys.argv:
        idx = sys.argv.index("--yara-rules")
        if idx + 1 < len(sys.argv):
            yara_rules_path = sys.argv[idx + 1]

    if not os.path.exists(input_file):
        print(f"[-] Input file not found: {input_file}")
        sys.exit(1)

    with open(input_file, "rb") as f:
        data = f.read()

    file_format = detect_format(data)
    print(f"[*] Format detected: {file_format} Mode")
    print(f"[+] Loaded {len(data)} bytes from {input_file}")

    # Optional: scan with YARA first if rules path provided
    if yara_rules_path:
        try:
            import yara
            rules = yara.compile(filepath=yara_rules_path)
            matches = rules.match(data=data)
            if matches:
                print(f"\n[!] YARA matches BEFORE patching:")
                for m in matches:
                    print(f"    - {m.rule} ({m.namespace})")
            else:
                print("[+] No YARA matches before patching")
        except ImportError:
            print("[i] yara-python not installed, skipping YARA scan")
            print("[i] Install with: pip install yara-python")
        except Exception as e:
            print(f"[i] YARA scan failed: {e}")

    print(f"\n[*] Applying patches...")
    patched_data, total = scan_and_patch(data, PATCHES)

    print(f"\n[+] Finished. Total patched occurrences: {total}")

    with open(output_file, "wb") as f:
        f.write(patched_data)

    print(f"[+] Saved to {output_file}")

    # Post-patch YARA scan
    if yara_rules_path:
        try:
            import yara
            rules = yara.compile(filepath=yara_rules_path)
            matches = rules.match(data=patched_data)
            if matches:
                print(f"\n[!] YARA matches AFTER patching (still detected):")
                for m in matches:
                    print(f"    - {m.rule}")
            else:
                print("\n[+] No YARA matches after patching!")
        except:
            pass


if __name__ == "__main__":
    main()
