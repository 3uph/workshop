# DEF CON Workshop PoC — Step-by-Step Malware Development: Evading EDR

Reconstructed code from the DEF CON workshop on EDR evasion techniques.
For authorized security testing and educational purposes only.

## Project Structure

```
1_Loader/
├── config.conf                    # Payload configuration
├── common.h                       # Shared utilities (config parser, payload loader)
├── build_all.bat                  # Windows build script (MSVC)
├── binfile/                       # Shellcode payloads (.bin)
│
├── 1.1_createThread/              # Part 1: Basic Execution
├── 1.2a_createRemoteThread/       #   All use MEM_PRIVATE → detected by Elastic
├── 1.2b_APCInjection/
├── 1.3_localThreadHijack/
├── 1.4_Fiber/
├── 1.5_simpleRunner/
│
├── 2.0_moduleStomping/            # Part 2: Memory Placement
├── 2.1_sectionMapping/            #   Uses MEM_IMAGE → evades unbacked rules
│
├── 3.1_stackSpoofing/             # Part 3: Stack Spoofing
├── 3.2_stackSpoofingIndirectSyscalls/  # + Indirect Syscalls
├── 3.3_stackSpoofingStomping/     # Combined: all three techniques
│
├── 4_AI/                          # Part 4: AI Evasion (dummy app wrapper)
│
├── tools/
│   ├── generate_shellcode.sh      # msfvenom shellcode generator
│   ├── crossbuild.sh              # Cross-compile from Kali
│   └── mypatch.py                 # YARA signature bypass tool
│
└── havoc/
    └── SETUP.md                   # Havoc C2 teamserver setup guide
```

## Quick Start

### 1. Generate Test Shellcode (on Kali)
```bash
chmod +x tools/generate_shellcode.sh
bash tools/generate_shellcode.sh
```

### 2. Build Loaders

**Option A: Cross-compile on Kali**
```bash
chmod +x tools/crossbuild.sh
bash tools/crossbuild.sh
```

**Option B: Build on Windows (MSVC)**
```cmd
build_all.bat
```

### 3. Configure Payload
Edit `config.conf`:
```ini
[config]
payload_type=local
payload_path=binfile\message.bin
```

### 4. Run on Windows Target
Transfer loader + config.conf + binfile/ to Windows machine with Elastic Defend
in **Detection mode** (not Prevention).

## Detection Matrix

| Technique | MEM_IMAGE? | New Thread? | Elastic Result |
|-----------|-----------|-------------|----------------|
| CreateThread | No | Yes | CAUGHT |
| CreateRemoteThread | No | Yes | CAUGHT |
| APC Injection | No | No | CAUGHT |
| Thread Hijacking | No | Depends | CAUGHT |
| Fiber Execution | No | No | CAUGHT |
| Simple Runner | No | No | CAUGHT |
| Module Stomp (sys32) | Yes | Yes | CAUGHT |
| **Module Stomp (non-sys32)** | **Yes** | **Yes** | **PASS** |
| **Stomp + Fiber** | **Yes** | **No** | **PASS** |
| Stack Spoofing only | No | No | CAUGHT (ROP gadget) |
| Spoofing + Indirect Syscalls | No | No | Partial |
| **Stomp + Spoof + Indirect** | **Yes** | **No** | **PASS** |

## Havoc C2 Setup
See `havoc/SETUP.md` for full teamserver deployment guide.
