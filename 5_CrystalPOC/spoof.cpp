#include <windows.h>
#include <stdio.h>
#include "spoof.h"

// ============================================================
// UNWIND_INFO types (not in public headers)
// ============================================================
typedef unsigned char UBYTE;

typedef union _UNWIND_CODE_U {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE_U;

typedef struct _UNWIND_INFO_S {
    UBYTE Version       : 3;
    UBYTE Flags         : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset   : 4;
    UNWIND_CODE_U UnwindCode[1];
} UNWIND_INFO_S;

enum UNWIND_OPS {
    UWOP_PUSH_NONVOL     = 0,
    UWOP_ALLOC_LARGE     = 1,
    UWOP_ALLOC_SMALL     = 2,
    UWOP_SET_FPREG       = 3,
    UWOP_SAVE_NONVOL     = 4,
    UWOP_SAVE_NONVOL_FAR = 5,
    UWOP_SAVE_XMM128     = 8,
    UWOP_SAVE_XMM128_FAR = 9,
    UWOP_PUSH_MACHFRAME  = 10
};

#define RBP_OP_INFO 0x5

// ============================================================
// Internal types
// ============================================================
typedef struct {
    PVOID ModuleAddress;
    PVOID FunctionAddress;
    DWORD Offset;
} FRAME_INFO;

typedef struct {
    FRAME_INFO Frame1;   // BaseThreadInitThunk
    FRAME_INFO Frame2;   // RtlUserThreadStart
    PVOID      Gadget;   // module containing jmp [rbx] gadgets
} SYNTHETIC_STACK_FRAME;

// ============================================================
// Dynamic imports
// ============================================================
typedef PRUNTIME_FUNCTION (WINAPI* RtlLookupFunctionEntry_t)(
    DWORD64 ControlPc, PDWORD64 ImageBase, PVOID HistoryTable);
typedef ULONG (NTAPI* RtlRandomEx_t)(PULONG Seed);

static RtlLookupFunctionEntry_t pRtlLookupFunctionEntry = NULL;
static RtlRandomEx_t            pRtlRandomEx             = NULL;

// ============================================================
// Global state
// ============================================================
static SYNTHETIC_STACK_FRAME g_frame   = {0};
static PVOID  g_gadgets[15]            = {0};
static DWORD  g_gadget_count           = 0;
static DWORD  g_gadget_index           = 0;

// ============================================================
// ASM extern
// ============================================================
extern "C" PVOID draugr_stub(
    PVOID, PVOID, PVOID, PVOID,
    DRAUGR_PARAMETERS*, PVOID, SIZE_T,
    PVOID, PVOID, PVOID, PVOID,
    PVOID, PVOID, PVOID, PVOID);

// ============================================================
// find .text section VA and size in a PE module
// ============================================================
static BOOL get_text_section(PVOID module, PDWORD va, PDWORD size) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((UINT_PTR)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            *va   = sec[i].VirtualAddress;
            *size = sec[i].SizeOfRawData;
            return TRUE;
        }
    }
    return FALSE;
}

// ============================================================
// calculate function stack size by parsing UNWIND_INFO
// ============================================================
static PVOID calculate_stack_size(RUNTIME_FUNCTION* rf, DWORD64 imageBase) {
    if (!rf) return NULL;

    UNWIND_INFO_S* ui = (UNWIND_INFO_S*)(rf->UnwindData + imageBase);
    ULONG     index     = 0;
    ULONGLONG totalSize = 0;

    while (index < ui->CountOfCodes) {
        ULONG op   = ui->UnwindCode[index].UnwindOp;
        ULONG info = ui->UnwindCode[index].OpInfo;

        if (op == UWOP_PUSH_NONVOL) {
            totalSize += 8;
        } else if (op == UWOP_SAVE_NONVOL) {
            index += 1;
        } else if (op == UWOP_ALLOC_SMALL) {
            totalSize += ((info * 8) + 8);
        } else if (op == UWOP_ALLOC_LARGE) {
            index += 1;
            ULONG frameOffset = ui->UnwindCode[index].FrameOffset;
            if (info == 0) {
                frameOffset *= 8;
            } else {
                index += 1;
                frameOffset += (ui->UnwindCode[index].FrameOffset << 16);
            }
            totalSize += frameOffset;
        } else if (op == UWOP_SET_FPREG) {
            // nothing to add
        } else if (op == UWOP_SAVE_XMM128) {
            return NULL;
        }
        index += 1;
    }

    if (ui->Flags & UNW_FLAG_CHAININFO) {
        index = ui->CountOfCodes;
        if (index & 1) index += 1;
        RUNTIME_FUNCTION* chained = (RUNTIME_FUNCTION*)(&ui->UnwindCode[index]);
        return calculate_stack_size(chained, imageBase);
    }

    totalSize += 8; // return address
    return (PVOID)totalSize;
}

static PVOID calculate_stack_size_for_addr(PVOID addr) {
    if (!addr || !pRtlLookupFunctionEntry) return NULL;

    DWORD64 imageBase = 0;
    RUNTIME_FUNCTION* rf = pRtlLookupFunctionEntry(
        (DWORD64)addr, &imageBase, NULL);
    if (!rf) return NULL;

    return calculate_stack_size(rf, imageBase);
}

// ============================================================
// scan for jmp [rbx] (FF 23) gadgets preceded by call (E8)
// ============================================================
static void scan_gadgets(PVOID module) {
    DWORD textVA = 0, textSize = 0;
    if (!get_text_section(module, &textVA, &textSize))
        return;

    PBYTE text = (PBYTE)((UINT_PTR)module + textVA);
    g_gadget_count = 0;

    for (DWORD i = 5; i < (textSize - 2) && g_gadget_count < 15; i++) {
        if (text[i] == 0xFF && text[i + 1] == 0x23 && text[i - 5] == 0xE8) {
            g_gadgets[g_gadget_count++] = (PVOID)((UINT_PTR)text + i);
        }
    }
}

static PVOID next_gadget() {
    if (g_gadget_count == 0) return NULL;
    PVOID g = g_gadgets[g_gadget_index % g_gadget_count];
    g_gadget_index++;
    return g;
}

// ============================================================
// SpoofInit — resolve dependencies and find gadgets
// ============================================================
BOOL SpoofInit() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll    = GetModuleHandleA("ntdll.dll");

    pRtlLookupFunctionEntry = (RtlLookupFunctionEntry_t)
        GetProcAddress(hKernel32, "RtlLookupFunctionEntry");
    pRtlRandomEx = (RtlRandomEx_t)
        GetProcAddress(hNtdll, "RtlRandomEx");

    if (!pRtlLookupFunctionEntry) {
        printf("    [-] RtlLookupFunctionEntry not found\n");
        return FALSE;
    }

    // BaseThreadInitThunk (kernel32)
    g_frame.Frame1.ModuleAddress   = (PVOID)hKernel32;
    g_frame.Frame1.FunctionAddress = (PVOID)GetProcAddress(hKernel32, "BaseThreadInitThunk");
    g_frame.Frame1.Offset          = 0x17;

    // RtlUserThreadStart (ntdll)
    g_frame.Frame2.ModuleAddress   = (PVOID)hNtdll;
    g_frame.Frame2.FunctionAddress = (PVOID)GetProcAddress(hNtdll, "RtlUserThreadStart");
    g_frame.Frame2.Offset          = 0x2c;

    if (!g_frame.Frame1.FunctionAddress || !g_frame.Frame2.FunctionAddress) {
        printf("    [-] BaseThreadInitThunk or RtlUserThreadStart not found\n");
        return FALSE;
    }

    // load dfshim.dll for gadgets (fallback to KernelBase.dll)
    g_frame.Gadget = (PVOID)GetModuleHandleA("dfshim.dll");
    if (!g_frame.Gadget)
        g_frame.Gadget = (PVOID)LoadLibraryA("dfshim.dll");
    if (!g_frame.Gadget)
        g_frame.Gadget = (PVOID)GetModuleHandleA("KernelBase.dll");

    if (!g_frame.Gadget) {
        printf("    [-] No suitable gadget module found\n");
        return FALSE;
    }

    scan_gadgets(g_frame.Gadget);

    if (g_gadget_count == 0) {
        printf("    [-] No jmp [rbx] gadgets found\n");
        return FALSE;
    }

    printf("    BaseThreadInitThunk: %p\n", g_frame.Frame1.FunctionAddress);
    printf("    RtlUserThreadStart:  %p\n", g_frame.Frame2.FunctionAddress);
    printf("    Gadget module:       %p\n", g_frame.Gadget);
    printf("    Found %lu jmp [rbx] gadgets\n", g_gadget_count);

    return TRUE;
}

// ============================================================
// draugr_wrapper — build params and invoke draugr_stub
// ============================================================
static ULONG_PTR draugr_wrapper(
    PVOID function,
    PVOID a1,  PVOID a2,  PVOID a3,  PVOID a4,
    PVOID a5,  PVOID a6,  PVOID a7,  PVOID a8,
    PVOID a9,  PVOID a10, PVOID a11, PVOID a12)
{
    DRAUGR_PARAMETERS params = {0};

    // BaseThreadInitThunk return address and stack size
    PVOID retAddr = (PVOID)((UINT_PTR)g_frame.Frame1.FunctionAddress + g_frame.Frame1.Offset);
    params.BaseThreadInitThunkStackSize     = calculate_stack_size_for_addr(retAddr);
    params.BaseThreadInitThunkReturnAddress = retAddr;

    if (!params.BaseThreadInitThunkStackSize || !params.BaseThreadInitThunkReturnAddress)
        return (ULONG_PTR)NULL;

    // RtlUserThreadStart return address and stack size
    retAddr = (PVOID)((UINT_PTR)g_frame.Frame2.FunctionAddress + g_frame.Frame2.Offset);
    params.RtlUserThreadStartStackSize     = calculate_stack_size_for_addr(retAddr);
    params.RtlUserThreadStartReturnAddress = retAddr;

    if (!params.RtlUserThreadStartStackSize || !params.RtlUserThreadStartReturnAddress)
        return (ULONG_PTR)NULL;

    // find a gadget with stack size >= 0x80
    int attempts = 0;
    do {
        params.Trampoline          = next_gadget();
        params.TrampolineStackSize = calculate_stack_size_for_addr(params.Trampoline);
        attempts++;
        if (attempts > (int)g_gadget_count)
            return (ULONG_PTR)NULL;
    } while (!params.TrampolineStackSize ||
             ((__int64)params.TrampolineStackSize < 0x80));

    return (ULONG_PTR)draugr_stub(
        a1, a2, a3, a4,
        &params, function, 8,
        a5, a6, a7, a8,
        a9, a10, a11, a12);
}

// ============================================================
// SpoofCall — public API, dispatches any FUNCTION_CALL
// ============================================================
ULONG_PTR SpoofCall(FUNCTION_CALL* call) {
    PVOID a[12] = {0};
    for (int i = 0; i < call->argc && i < 12; i++)
        a[i] = (PVOID)call->args[i];

    return draugr_wrapper(
        call->ptr,
        a[0], a[1], a[2],  a[3],
        a[4], a[5], a[6],  a[7],
        a[8], a[9], a[10], a[11]);
}
