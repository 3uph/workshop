#pragma once
#include <windows.h>

// Spoof context holds the gadget and frame addresses found in ntdll
struct SpoofContext {
    PVOID Gadget;        // Address of 'call r12' gadget in ntdll
    PVOID Frame1;        // Additional frame addresses for realistic stack
    PVOID Frame2;
    BOOL  Ready;
};

// Patch call descriptor - describes a spoofed API call
struct PatchCall {
    PVOID  Function;     // Target API to call (e.g. VirtualProtect)
    DWORD  nArgs;        // Number of arguments
    PVOID  Gadget;       // ntdll gadget address
    PVOID  Args[8];      // Arguments to the API
};

// ASM functions (defined in asm.asm)
extern "C" void Do_Call(PatchCall* call);
extern "C" void Fixup();

// Initialize spoof context by scanning ntdll for gadgets
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
    ctx->Ready = FALSE;

    // Search for 'call r12' (41 FF D4) and 'syscall; ret' (0F 05 C3) gadgets
    for (PBYTE cur = base; cur <= base + size - 3; cur++) {
        if (!ctx->Gadget && cur[0] == 0x41 && cur[1] == 0xFF && cur[2] == 0xD4) {
            ctx->Gadget = cur;
        }
        if (ctx->Gadget) break;
    }

    if (ctx->Gadget) {
        ctx->Ready = TRUE;
        printf("[+] Gadget : %p\n", ctx->Gadget);
    }

    // Find two legitimate return addresses in ntdll for frame spoofing
    ctx->Frame1 = (PVOID)GetProcAddress(hNtdll, "RtlUserThreadStart");
    ctx->Frame2 = (PVOID)GetProcAddress(hNtdll, "RtlInitializeExceptionChain");
    if (ctx->Frame1) printf("[+] Frame1 : %p\n", ctx->Frame1);
    if (ctx->Frame2) printf("[+] Frame2 : %p\n", ctx->Frame2);

    return ctx->Ready;
}

// Call VirtualProtect with return address spoofing
static BOOL SpoofedVirtualProtect(SpoofContext* ctx, LPVOID addr, SIZE_T size,
                                   DWORD newProtect, PDWORD oldProtect) {
    if (!ctx->Ready) {
        return VirtualProtect(addr, size, newProtect, oldProtect);
    }

    PatchCall call;
    call.Function = (PVOID)VirtualProtect;
    call.nArgs = 4;
    call.Gadget = ctx->Gadget;
    call.Args[0] = addr;
    call.Args[1] = (PVOID)size;
    call.Args[2] = (PVOID)(ULONG_PTR)newProtect;
    call.Args[3] = (PVOID)oldProtect;

    Do_Call(&call);
    return (*oldProtect != 0);
}
