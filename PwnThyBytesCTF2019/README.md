# Unconventional

    Description:
    
    I just started learning x86 assembly and already have so many questions, such as:

    - Why do they call them "General Purpose Registers" if you can use only some of them in some instructions?
    - Why are there so many instructions that nobody uses?
    - And what's this "calling convention" everybody keeps telling me about?

"Unconventional" is a x86_64 Linux binary in a malformed format requiring input and answering depending whether the flag is correct.

## Solution

As the binary is in a weirdly broken format executing it directly with gdb doesn't work, but this is no problem because attaching to it during the waiting for input works just fine.

Initially stepping through it showed quite a bit of self-modifying code using floating point instructions, so my first step was to write a script to filter them out and give a more clean instruction trace:

```python
# 1. Run ./unconventional
# 2. Figure out the pid of it
# 3. Attach gdb to it ("attach <pid>")
# 4. Enter a string into the terminal of the binary
# 5. "source unconv.py"

lastInst = ""
firstNop = False
interesting = False
f = open("trace.txt", "w") # open a file to output a trace

try:
    while True:
        curValue = int(gdb.parse_and_eval("*((unsigned char*)($rip))"))&0xFF # read the opcode of the current instruction
        curInst = gdb.execute("x/i $rip", to_string=True) # read the disassembly for the current instruction
        
        if curValue == 0x90: # if the instruction is the first "nop" after other instructions, the instruction executed before is the result of self modifying code
            if firstNop: 
                f.write(lastInst[3:])
            firstNop = False # not the first nop
        else:
            firstNop = True  # if a normal instruction is executed the instruction before the next nop is interesting
            
        if "fisttp" in lastInst:  # the jmp rax and other interesting instructions are getting executed after fisttp's
            interesting = True
         
        if ("mov" in curInst and "0x90" in curInst) or ("fi" in curInst) or ("fstp" in curInst):  #when these parts are in the current instruction then nothing interesting happens
            interesting = False
        
        if interesting:   # output jumps and in between instructions (some are not relevant, but more information is better)
            f.write(curInst[3:])

        lastInst = curInst
        gdb.execute("si")  # step to the next instruction
except Exception:
    pass # when the program ends an exception is thrown, ignore it and close the file
    
f.close()
```

To start with the trace I looked at what decides whether a "NO" is written and found out that the lower half of the registers r8, r9, r10, r12, r13, r14 and r15 are compared to their upper half and if all of them match "YE" is printed instead.

Example of the comparison of upper and lower half of the registers:

```nasm
0x406011:	mov    rsp,0x1    # start rsp with a 1 so it can be set 0 if half of a register don't match
...
0x403ca2:	mov    rax,r8     # set rax to the register checked
0x403d0d:	shr    rax,0x20   # shift it right by 32 bits to it only contains the upper half of the original register
0x403d78:	mov    rbx,r8     # set rbx to the register checked
0x403de3:	shl    rbx,0x20   # shift it left to remove the upper 32 bits
0x403e43:	shr    rbx,0x20   # shift it back right so it now only contains the lower half of the original register
0x403eae:	cmp    rax,rbx    # check if upper and lower half of the register in question match
0x403f1c:	sete   al         # depending on the result set al
0x403f8e:	and    rsp,rax    # either keep the rsp value if half match or set it 0 if not
...
0x4060a9:	test   rsp,rsp    # check if all registers have matching half
0x4060e6:	je     0x4060f1   # "YE" or "NO"
```


Looking through the trace and stepping through them in a debugger shows that for each character code like this is executed:

```
0x401d67:	jb     0x40255b
0x401da2:	shl    r8,1
0x401e1e:	sahf   
0x401e69:	js     0x402632
0x401ea4:	shl    r9,1
0x401f24:	sahf   
0x401f6f:	je     0x40270d
0x401faa:	shl    r10,1
0x40202a:	sahf   
0x402075:	jp     0x4027e8
0x402819:	shl    r12,1
0x402884:	or     r12,0x1
```

Part of the code for each character also looks the following, which is an interesting switch to 32bit mode and back to execute the `aas` instruction which was removed in the x86_64 instruction set.

```nasm
0x4021f7:	jmp    FWORD PTR [rip+0x8]        # 0x402205
0x4021fd:	(bad)                             # aas
0x4021fe:	(bad)                             # ljmp 0x33:0x40220b
0x40220b:	jb     0x4028bf
```

Regardless the more interesting part is that the registers are shifted left once for each character, and depending on whether the jumps are taken or not the first bit in the registers is set.

Because this is done 32 times the upper 32 bit of the registers are the initial lower half of them before processing the input.

At the start the relevant registers contain the following values so this is the pattern to match at the end:

```
// Start Value (can be read for example at 0x405e64)
 R8   0x7f7f7f80
 R9   0x5bdbd764
 R10  0xfecac280
 R12  0x69b5bd90
 R13  0x8ac68ad8
 R14  0x61819da6
 R15  0x7ffffffe
```

After looking at the output of input filled with A's my first idea was that depending on the bits of the input the bits of the registers are set:

```
// AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (0b1000001, can be read for example at 0x40606c)
 R8   0x7f7f7f8000000000  <- 0 bits set
 R9   0x5bdbd76400000000  <- 0 bits set
 R10  0xfecac28000000000  <- 0 bits set
 R12  0x69b5bd90fffffffe  <- 31 bits set
 R13  0x8ac68ad800000000  <- 0 bits set
 R14  0x61819da600000000  <- 0 bits set
 R15  0x7ffffffefffffffe  <- 31 bits set
```

Trying different input made it likely that my assumption is correct:

```

// BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB (0b1000010)
 R8   0x7f7f7f8000000000
 R9   0x5bdbd76400000000
 R10  0xfecac28000000000
 R12  0x69b5bd9000000000
 R13  0x8ac68ad8fffffffe
 R14  0x61819da600000000
 R15  0x7ffffffefffffffe

// DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD (0b1000100)
 R8   0x7f7f7f8000000000
 R9   0x5bdbd764fffffffe
 R10  0xfecac28000000000
 R12  0x69b5bd9000000000
 R13  0x8ac68ad800000000
 R14  0x61819da600000000
 R15  0x7ffffffefffffffe

// HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH (0b1001000)
 R8   0x7f7f7f8000000000
 R9   0x5bdbd76400000000
 R10  0xfecac280fffffffe
 R12  0x69b5bd9000000000
 R13  0x8ac68ad800000000
 R14  0x61819da600000000
 R15  0x7ffffffefffffffe

// aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (0b1100001)
R8   0x7f7f7f80fffffffe
R9   0x5bdbd76400000000
R10  0xfecac28000000000
R12  0x69b5bd90fffffffe
R13  0x8ac68ad800000000
R14  0x61819da600000000
R15  0x7ffffffefffffffe
```

Based on the sampled input to output sets I assigned the registers to the bit probably responsible for changing them and sorted them:

```
 R12 = bit 0
 R13 = bit 1
 R9  = bit 2
 R10 = bit 3
 R14 = bit 4
 R8  = bit 5
 R15 = bit 6
```

Putting the initial register values that need to be matched in the correct order reveals the flag:

```python
def solution():
    solution = []
    bits = [0x69b5bd90, 0x8ac68ad8, 0x5bdbd764, 0xfecac280, 0x61819da6, 0x7f7f7f80, 0x7ffffffe]
    for j in range(0x20):
        bitStr = "0" + ''.join([str(bits[i]&1) for i in range(7)][::-1])
        c    = chr(int(bitStr,2))
        solution.append(c)
        for i in range(7):
            bits[i] = bits[i] >> 1
    return ''.join(solution)
```

```
>>> print(solution())
 PTBCTF{unusual_unclean_unholy}
```