#pragma once
#include <windows.h>

#define spoof_arg(x) (ULONG_PTR)(x)

typedef struct _FUNCTION_CALL {
    PVOID     ptr;
    int       argc;
    ULONG_PTR args[12];
} FUNCTION_CALL;

// DRAUGR_PARAMETERS — layout must match draugr.asm offsets exactly
typedef struct _DRAUGR_PARAMETERS {
    PVOID Fixup;                              // +0
    PVOID OriginalReturnAddress;              // +8
    PVOID Rbx;                                // +16
    PVOID Rdi;                                // +24
    PVOID BaseThreadInitThunkStackSize;       // +32
    PVOID BaseThreadInitThunkReturnAddress;   // +40
    PVOID TrampolineStackSize;               // +48
    PVOID RtlUserThreadStartStackSize;       // +56
    PVOID RtlUserThreadStartReturnAddress;   // +64
    PVOID Ssn;                               // +72
    PVOID Trampoline;                        // +80
    PVOID Rsi;                               // +88
    PVOID R12;                               // +96
    PVOID R13;                               // +104
    PVOID R14;                               // +112
    PVOID R15;                               // +120
} DRAUGR_PARAMETERS;

BOOL SpoofInit();
ULONG_PTR SpoofCall(FUNCTION_CALL* call);
