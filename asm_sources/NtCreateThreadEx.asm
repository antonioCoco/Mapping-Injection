;C:\fasm\fasm.exe NtCreateThreadEx.asm NtCreateThreadEx.bin
;python bin2cbuffer.py NtCreateThreadEx.bin NtCreateThreadExCode
use64
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