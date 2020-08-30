format ELF64 executable

segment readable executable
  entry $
  
start:
xor rax, rax
xor rbx, rbx
xor rcx, rcx
xor rdx, rdx
xor rsi, rsi
xor rdi, rdi
xor r8, r8
xor r9, r9
xor r10, r10
j0000:  mov bx, 0x7000
j0026:  lea rax, qword [rbx]
j004A:  mov word [rax], 0x1
j006C:  lea rax, qword [0x2 + rbx]
j0095:  mov word [rax], 0x1
j00B7:  mov cx, 0x2
j00DA:  lea rdi, qword [rcx + rcx]
j0108:  lea rax, qword [0x7000 + rdi]
j0136:  mov si, word [rax]
j015B:  cmp sil, 0
jnz j0324
j0180:  lea rdx, qword [rcx + rcx]
j01AE:  mov ax, 0xffef
j01D4:  mov word [rax], dx
j01F9:  mov ax, 0xfff0
j021F:  mov si, word [rax]
j0244:  cmp sil, 0
jnz j0324
j0269:  lea rdi, qword [rdx + rdx]
j0297:  lea rax, qword [0x7000 + rdi]
j02C5:  mov word [rax], 0x1
j02E7:  lea rdx, qword [rdx + rcx]
j0315:  jmp j01AE
j0324:  lea rcx, qword [0x1 + rcx]
j034F:  cmp cl, 0
jnz j00DA
j0374:  mov bx, 0xe000
j039A:  mov cx, 0x0
j03BD:  lea rax, qword [rbx]
j03E1:  mov dx, word [rax]
j0406:  cmp dl, 0
jnz j043A
j042B:  jmp j04A1
j043A:  lea rcx, qword [0xffff + rcx]
j0469:  lea rbx, qword [0x1 + rbx]
j0492:  jmp j03BD
j04A1:  lea rdi, qword [0xfe + rcx]
j04D0:  cmp dil, 0
jnz j0504
j04F5:  jmp j0536
j0504:  mov r10w, 0x5
j0527:  jmp j13D9
j0536:  mov bx, 0x0
j0558:  mov cx, 0x0
j057B:  mov ax, 0xf100
j05A1:  mov dx, word [rax]
j05C6:  mov si, 0x1
j05E9:  mov r10w, 0x0
j060C:  lea rax, qword [0xe000 + rbx]
j0639:  mov di, word [rax]
j065E:  cmp dil, 0
jnz j0692
j0683:  jmp j0D97
j0692:  lea rbx, qword [0x1 + rbx]
j06BB:  lea r8, qword [0xff8b + rdi]
j06EA:  cmp r8b, 0
jnz j0745
j070F:  mov di, 0xfff0
j0736:  jmp j0945
j0745:  lea r8, qword [0xff8e + rdi]
j0774:  cmp r8b, 0
jnz j07CB
j0799:  mov di, 0x1
j07BC:  jmp j0945
j07CB:  lea r8, qword [0xff9c + rdi]
j07FA:  cmp r8b, 0
jnz j0852
j081F:  mov di, 0x10
j0843:  jmp j0945
j0852:  lea r8, qword [0xff94 + rdi]
j0881:  cmp r8b, 0
jnz j08DC
j08A6:  mov di, 0xffff
j08CD:  jmp j0945
j08DC:  mov si, 0x0
j08FF:  mov di, 0x0
j0922:  mov r10w, 0x1
j0945:  lea rdx, qword [rdx + rdi]
j0973:  mov ax, 0xffef
j0999:  mov word [rax], dx
j09BE:  mov ax, 0xfff0
j09E4:  mov di, word [rax]
j0A09:  cmp dil, 0
jnz j0D65
j0A2E:  lea rax, qword [0xf000 + rdx]
j0A5C:  mov di, word [rax]
j0A81:  mov ax, 0xffef
j0AA7:  mov word [rax], di
j0ACC:  mov ax, 0xfff0
j0AF2:  mov word [rax], 0x0
j0B14:  mov ax, 0xffef
j0B3A:  mov di, word [rax]
j0B5F:  lea rdi, qword [rdi + rdi]
j0B8D:  lea rax, qword [0x7000 + rdi]
j0BBB:  mov di, word [rax]
j0BE0:  cmp dil, 0
jnz j0D10
j0C05:  lea rdi, qword [0x1 + rcx]
j0C30:  lea rax, qword [0xf102 + rdi]
j0C5E:  mov di, word [rax]
j0C83:  lea rdi, qword [rdi + rdx]
j0CB1:  cmp dil, 0
jnz j0D01
j0CD6:  lea rcx, qword [0x1 + rcx]
j0D01:  jmp j060C
j0D10:  mov si, 0x0
j0D33:  mov r10w, 0x2
j0D56:  jmp j060C
j0D65:  mov r10w, 0x4
j0D88:  jmp jFFFE
j0D97:  cmp sil, 0
jnz j0DCB
j0DBC:  jmp j13D9
j0DCB:  lea rdi, qword [0xfff7 + rcx]
j0DFA:  cmp dil, 0
jnz j0E2E
j0E1F:  jmp j0E60
j0E2E:  mov r10w, 0x3
j0E51:  jmp j13D9
j0E60:  mov bx, 0x0
j0E82:  mov cx, 0x0
j0EA5:  lea rdx, qword [0xffd9 + rbx]
j0ED3:  cmp dl, 0
jnz j0F07
j0EF8:  jmp j137B
j0F07:  mov si, 0x4
j0F2A:  mov dx, 0x0
j0F4D:  lea rdx, qword [rdx + rdx]
j0F7B:  lea rdx, qword [rdx + rdx]
j0FA9:  lea rax, qword [0xe000 + rcx]
j0FD7:  mov di, word [rax]
j0FFC:  lea r8, qword [0xff8b + rdi]
j102B:  cmp r8b, 0
jnz j105F
j1050:  jmp j1218
j105F:  lea r8, qword [0xff8e + rdi]
j108E:  cmp r8b, 0
jnz j10ED
j10B3:  lea rdx, qword [0x1 + rdx]
j10DE:  jmp j1218
j10ED:  lea r8, qword [0xff9c + rdi]
j111C:  cmp r8b, 0
jnz j117B
j1141:  lea rdx, qword [0x2 + rdx]
j116C:  jmp j1218
j117B:  lea r8, qword [0xff94 + rdi]
j11AA:  cmp r8b, 0
jnz j1209
j11CF:  lea rdx, qword [0x3 + rdx]
j11FA:  jmp j1218
j1209:  jmp j13D9
j1218:  lea rcx, qword [0x1 + rcx]
j1243:  lea rsi, qword [0xffff + rsi]
j1272:  cmp sil, 0
jnz j0F4D
j1297:  lea rax, qword [0xf10c + rbx]
j12C4:  mov si, word [rax]
j12E9:  lea rax, qword [0xe800 + rbx]
j1316:  mov word [rax], si
add word [rax], dx
j1343:  lea rbx, qword [0x1 + rbx]
j136C:  jmp j0EA5
j137B:  lea rax, qword [0xe800 + rbx]
j13A8:  mov word [rax], 0x0
j13CA:  jmp jFFFE
j13D9:  mov ax, 0xe800
j13FF:  mov word [rax], 0x0
jFFFE: ret
jXXXX: ret