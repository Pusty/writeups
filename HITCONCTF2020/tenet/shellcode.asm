bits 64


mov rax, 0x02170000       ; set rax to the cookie
mov rdi, qword [rax]      ; read the cookie
mov [rax], rdi        
mov [rax+16], rdi         ; write the cookie to rax+16 (making it appear in the upper bits of the ymm register)
mov rdi, [rax+16] 
vmovups ymm0,yword [rax]  ; read the yword at rax
vmovups yword  [rax],ymm0
xor rdi, rdi              ; set rdi to 0
mov qword [rax], rdi      ; clear the cookie
mov qword [rax+16], rdi   ; clear the copy of the cookie
mov rax, 0x02170000     

mov eax, 0x3C             ; sys_exit / end of shellcode
syscall


; In Reverse
;syscall
;mov eax, 0x3C             ; sys_exit

;mov rax, 0x02170000       ; set rax to the cookie            
;mov qword [rax+16], rdi   ; zero already zeroed memory
;mov qword [rax], rdi
;xor rdi, rdi
;vmovups yword  [rax],ymm0 ; write ymm0 back (xmm0 was reset as such only the upper half is preserved)
;vmovups ymm0,yword [rax] 
;mov rdi, [rax+16]         ; read the upper copy of the cookie
;mov [rax+16], rdi         
;mov [rax], rdi            ; write the cookie back to the original position
;mov rdi, qword [rax]  
;mov rax, 0x02170000 


