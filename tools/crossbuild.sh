#!/bin/bash
# Cross-compile all loaders from Kali Linux to Windows x64
# Requires: apt install gcc-mingw-w64-x86-64 nasm

set -e
BASEDIR="$(cd "$(dirname "$0")/.." && pwd)"
CC="x86_64-w64-mingw32-gcc"
CFLAGS="-O2 -static -lwinhttp -lws2_32 -lstdc++"

echo "============================================"
echo "  Cross-compiling Workshop Loaders"
echo "============================================"
echo ""

# Part 1: Basic loaders (C++ only, no ASM needed)
for dir in 1.1_createThread 1.2a_createRemoteThread 1.2b_APCInjection \
           1.3_localThreadHijack 1.4_Fiber 1.5_simpleRunner; do
    echo "[*] Building $dir..."
    CPP=$(find "$BASEDIR/$dir" -name "*.cpp" | head -1)
    if [ -n "$CPP" ]; then
        NAME=$(basename "$CPP" .cpp)
        $CC "$CPP" -o "$BASEDIR/$dir/$NAME.exe" $CFLAGS -I"$BASEDIR" 2>&1 && \
            echo "[+] $NAME.exe built" || echo "[-] $NAME.exe FAILED"
    fi
done

# Part 2: Module Stomping loaders
for dir in 2.0_moduleStomping 2.1_sectionMapping; do
    echo "[*] Building $dir..."
    CPP=$(find "$BASEDIR/$dir" -name "*.cpp" | head -1)
    if [ -n "$CPP" ]; then
        NAME=$(basename "$CPP" .cpp)
        $CC "$CPP" -o "$BASEDIR/$dir/$NAME.exe" $CFLAGS -I"$BASEDIR" 2>&1 && \
            echo "[+] $NAME.exe built" || echo "[-] $NAME.exe FAILED"
    fi
done

# Part 3: Stack Spoofing (needs NASM for assembly)
echo ""
echo "[*] Building Part 3 (ASM + C++)..."

for dir in 3.1_stackSpoofing 3.2_stackSpoofingIndirectSyscalls 3.3_stackSpoofingStomping; do
    echo "[*] Building $dir..."
    ASM=$(find "$BASEDIR/$dir" -name "*.asm" | head -1)
    CPP=$(find "$BASEDIR/$dir" -name "*.cpp" | head -1)

    if [ -n "$ASM" ] && [ -n "$CPP" ]; then
        NAME=$(basename "$CPP" .cpp)
        # Assemble with NASM (Windows x64 format)
        echo "    Assembling $(basename $ASM)..."
        nasm -f win64 "$ASM" -o "$BASEDIR/$dir/asm.obj" 2>&1 && \
            echo "    [+] asm.obj created" || { echo "    [-] NASM failed"; continue; }

        # Link with gcc
        echo "    Compiling + linking..."
        $CC "$CPP" "$BASEDIR/$dir/asm.obj" -o "$BASEDIR/$dir/$NAME.exe" \
            $CFLAGS -I"$BASEDIR" 2>&1 && \
            echo "[+] $NAME.exe built" || echo "[-] $NAME.exe FAILED"
    fi
done

echo ""
echo "============================================"
echo "  Build Complete"
echo "============================================"
echo ""
echo "Binaries are in each technique's directory."
echo "Copy to Windows target along with config.conf and binfile/ directory."
echo ""
echo "Don't forget to generate shellcode first:"
echo "  bash tools/generate_shellcode.sh"
