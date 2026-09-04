#!/usr/bin/env python3
"""Convert a binary file to a C header with embedded byte array."""
import sys, os

if len(sys.argv) < 2:
    print("Usage: python bin2header.py <input.bin> [output.h]")
    sys.exit(1)

infile = sys.argv[1]
outfile = sys.argv[2] if len(sys.argv) > 2 else "payload.h"

with open(infile, "rb") as f:
    data = f.read()

with open(outfile, "w") as f:
    f.write("#pragma once\n")
    f.write(f"// Auto-generated from {os.path.basename(infile)}\n")
    f.write(f"// Size: {len(data)} bytes\n\n")
    f.write(f"unsigned char embedded_payload[] = {{\n")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        line = ", ".join(f"0x{b:02x}" for b in chunk)
        f.write(f"    {line},\n")
    f.write("};\n")
    f.write(f"unsigned int embedded_payload_size = {len(data)};\n")

print(f"[+] {len(data)} bytes -> {outfile}")
