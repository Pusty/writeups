# Binary Tree

    Uh, you can give the key. It's a binary search tree... I think?
    Author: rbtree
    
Binary Tree is a ELF file that takes 100 character input and verifies it through traversing a "binary search tree"

## Solution

Looking at the `_start` function, the program reads in 100 bytes of input and then maps each bit of the bytes in a big `bit_array`.
The program also contains a very big array of static data (named `big_data_array` here) and a "PASS" and "FAIL" string.

![](img/btree_start.png)

The actual interesting function is the self modifying function at address `0x400080`:

![](img/btree_selfmod.png)

In the high level view it is clearly possible to see that the function modifies itself based on the data pointed to by `rbx` / `bda_pointer`:
After the self modifying the code reads a bit from the `bit_array`, increases the `bit_array` pointer by one and runs `test al, al` to see if the bit is zero.
The instructions after that aren't actually executed as they are changed by the code before.

![](img/btree_selfmodh.png)

The code after the self modification looks like this:

```
0x4000ad:       nop
0x4000ae:       je      0x4000bd
0x4000b0:       lea     rbx, [rdi + 0x40]
0x4000b4:       nop
0x4000b5:       add     r9, 0x49
0x4000b9:       jmp     0x400080
0x4000bb:       nop
0x4000bc:       nop
0x4000bd:       lea     rbx, [rdi + 0x20]
0x4000c1:       nop
0x4000c2:       nop
0x4000c3:       nop
0x4000c4:       add     r9, 0x11
0x4000c8:       nop
0x4000c9:       nop
0x4000ca:       nop
0x4000cb:       jmp     0x400080
```


Now this is interesting:
The actual code that is executed uses the flags set by the `test` instruction to branch depending on the value of the bit of the input.
Depending on whether the bit is 0 or 1 one of two similar looking blocks of code is executed.
Both of them set `rbx` / `bda_pointer` to a new address absolute to `rdi` / `bda_address` / the `big_data_array`, add a value to `r9` and recursively jump back to the beginning of the function.

As `rbx` changed, depending on the branch the self-modifying-xor will reveal different new code.

The same semantic structure of code is revealed for all 800 bits of the input `bit_array`

After the 800th bit, the code is changed back to the original function (for now the assumption is that all paths recover the same original function):

```
0x4000ad:       mov     rax, 1
0x4000b4:       mov     rdi, 1
0x4000bb:       mov     rdx, 5
0x4000c2:       cmp     r9, 0x49da
0x4000c9:       jg      0x4000d2
0x4000cb:       mov     rsi, r10
0x4000ce:       syscall
0x4000d0:       jmp     0x4000d7
0x4000d2:       mov     rsi, r11
0x4000d5:       syscall
0x4000d7:       mov     rax, 0x3c
0x4000de:       xor     rdi, rdi
0x4000e1:       syscall
```

As the challenge description mentioned this can be viewed as a 800-depth binary search tree with weighted branches.
The goal is probably to find a 800 bit input for which the added weights of the taken branches is less or equal to the `MAGIC_VALUE` `0x49da` / `18906`.

The problem is that a full search of all paths is not feasible as a 800-depth binary search tree would have  `2**800 = 6668014432879854274079851790721257797144758322315908160396257811764037237817632071521432200871554290742929910593433240445888801654119365080363356052330830046095157579514014558463078285911814024728965016135886601981690748037476461291163877376` unique paths.
A Breadth-first search with trimming branches once they are higher than the `MAGIC_VALUE` also does not seem to be feasible as it seems to get stuck at around depth 200 which would still be `2**200 = 1606938044258990275541962092341162602522202993782792835301376` unique paths.


But wait! Does this being a binary search tree actually make sense?
No, because in a binary search tree each node does not only have 2 children (which this fulfills), but also has exactly one parent (which makes it a tree).
That would mean there are supposed to be `sum([2**i for i in range(801)])` nodes.
As `big_data_array` encodes the nodes and is only `816096` bytes in size, it can only encode `25503` nodes.
So this obviously can't be a tree, it is more of a binary search graph.


So which properties does this graph actually have?
There is an explicit start node, each node has two children, the graph is directed / each edge is unidirectional, there are multiple exit nodes, and each edge has a weight.
For now let's assume that the weights are all positive and not zero. Also we can be sure that from the start any 800 transitions a exit node will appear.

![](img/btree_graph0.png)


As the `MAGIC_VALUE` is not an exact value but just the maximum the correct solution is allowed to have, we can solve this by finding the path with the least cost from start to exit.
One method to do that is to calculate the minimal cost of arriving to a specific exit node backwards:

![](img/btree_graph.gif)

As the backwards calculated cost of a node can't get lower if all the children of it have been traversed, there is no need to traverse all paths anymore.
It is only required to traverse all nodes.

To work with the self-modifying code I used [capstone](https://www.capstone-engine.org/). 
The following script uses the above displayed method to find the shortest path:

```python

from capstone import *


loopFunc = 0x400080
loopFuncLen = 0x4000e1-loopFunc

bigdataArray = 0x400176
bigdataArrayLen = 0x4c7556-bigdataArray

MAGIC_VALUE = 0x49da


md = Cs(CS_ARCH_X86, CS_MODE_64)
binaryFile = open("main.elf", "rb")
data = binaryFile.read()

loopFuncMem = data[0x80:0x80+loopFuncLen]
bigArrayMem = data[0x176:0x176+bigdataArrayLen]

loopFuncMem = [b for b in loopFuncMem]
bigArrayMem = [b for b in bigArrayMem]

binaryFile.close()


# Actual Minimal Path Calculations

shortestPath = {}

def registerPath(path, add):
    revAdd = 0
    if path[-1] in shortestPath:
        revAdd = shortestPath[path[-1]]
    else:
        revAdd = add[-1]

    for r in range(1, len(path)+1):
        if r > 1: revAdd = revAdd + add[-r]
        if path[-r] in shortestPath:
            shortestPath[path[-r]] = min(shortestPath[path[-r]], revAdd)
        else:
            shortestPath[path[-r]] = revAdd

def parseBranch(mem, rbx, val, depth=0, path=[], add=[]):

   
    if rbx in shortestPath:
        registerPath(path, add)
        if shortestPath[rbx]+val > MAGIC_VALUE:
            return
    
    if depth == 100*8: 
        registerPath(path, add)
        return

    # apply self modifying xor
    for i in range(8*4):
        mem[i] ^= bigArrayMem[rbx+i]

    currentAdd = 0
    nextPointer = 0
    existingJumps = []
    
    for i in md.disasm(bytes(mem), 0x2d):
        op = i.mnemonic
        if op == "nop": 
            continue
        if op == "je":
            continue
        if op == "jmp":
            existingJumps.append((nextPointer, currentAdd))
            continue
        if op == "add":
            currentAdd = int(i.op_str.split(",")[1].strip(), 16)
            continue
        if op == "lea":
            nextPointer = int(i.op_str.split("+")[1].split("]")[0].strip(), 16)
            continue
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)) # print if unexpected stuff occurs
    
    for (nextPointer, currentAdd)  in existingJumps:
        parseBranch(mem+[], nextPointer, val+currentAdd, depth+1, path+[nextPointer], add+[currentAdd])
    
# calculate shortest paths
parseBranch(loopFuncMem[0x2d:], 0, 0)
```

Interestingly the script gets "stuck" at ~depth 400 and 200 again, but looking into it, the paths taking up most of the time are unlikely to lead to the solution anyways, so trimming them solves it waaay faster:

```python
        # this prevents unnecessary calculations
        if shortestPath[rbx]+val > 14000 and depth < 400:
            return
            
        if shortestPath[rbx]+val > 12000 and depth < 200:
            return
```


With the data of the shortest paths we can easily traverse the graph:

![](img/btree_finish.gif)


```python
def verboseCalc(mem, rbx, val, depth=0, bits=[]):

    if depth == 100*8: 
        barray = ''.join('0' if b == 0 else '1' for b in bits)
        # print flag
        print(''.join([chr(int(barray[i*8:(i+1)*8][::-1],2)) for i in range(len(barray)//8)]))
        return
        
    # apply self modifying xor
    for i in range(8*4):
        mem[i] ^= bigArrayMem[rbx+i]

    currentAdd = 0
    nextPointer = 0
    
    
    existingJumps = []
    
    for i in md.disasm(bytes(mem), 0x2d):
        op = i.mnemonic
        if op == "jmp":
            existingJumps.append((nextPointer, currentAdd))
        if op == "add":
            currentAdd = int(i.op_str.split(",")[1].strip(), 16)
        if op == "lea":
            nextPointer = int(i.op_str.split("+")[1].split("]")[0].strip(), 16)
    
    jo = shortestPath[existingJumps[0][0]]
    jz = shortestPath[existingJumps[1][0]]

    if jo+val == MAGIC_VALUE:
        verboseCalc(mem+[], existingJumps[0][0], val+existingJumps[0][1], depth+1, bits+[1])
    if jz+val == MAGIC_VALUE:
        verboseCalc(mem+[], existingJumps[1][0], val+existingJumps[1][1], depth+1, bits+[0])

# use shortest paths map and traverse it
verboseCalc(loopFuncMem[0x2d:], 0, 0)
```

Through all the optimization we just run the [script](solve.py) and get the flag within a few seconds

    >python solve.py
    pbctf{!!finding_the_shortest_path_in_self-modifying_code!!_e74c30e30bb22a478ac513c9017f1b2608abfee7}
    
# Cosmo

    To make it fair for everyone, this binary is fully portable. Run it anywhere! This definitely makes it easier, right?
    Author: UnblvR
    
Cosmo is a password verification program compiled with [Cosmopolitan](https://github.com/jart/cosmopolitan)

## Solution


The binary contains a lot of code for the cross platform features.
Figuring out what belongs to the actual challenge is the first step, running strings helps here:

```
> strings hello.com
...
Give flag
Correct!
...
```

Checking where those strings are referenced in the code leads to the main function:

![](img/cosmo_cref.png)


Checking the main function and making some assumptions, a lot of the code can be easily labeled:

![](img/cosmo_main.png)

The `checksumFunction` was labeled as such, as it takes the previous return values and parts of the input and calculates the next round based on it.
The return value of each round is compared against entries of a hardcoded array:

![](img/cosmo_checksums.png)

Looking in the `checksumFunction` shows a lot of mathematical operations, especially the `packedCompliactedMathThings` function is complex.
As it seems that it only checks 2 bytes of input each time it is possible to bruteforce the checksums.
An easy way to do that would be to reuse the existing code. With a bit more effort reimplementing the function is also possible.
I did none of these things and instead googled for the constants and special cases:

![](img/cosmo_checksumFunc.png)

Interestingly one of the constants actually yielded a result:

`0xfff1 = 65521`:

`define BASE 65521U     /* largest prime smaller than 65536 */`
in zlibs [adler32.c](https://github.com/madler/zlib/blob/master/adler32.c)

Looking at the structure of the implementation, it seems reasonable that it is indeed the correct checksum algorithm:

![](img/cosmo_adler32.png)

A quick python implementation of the code reveals the flag:

```python
import zlib

checksums = [
	0x00000000014400d3, 0x00000000042401aa,
	0x0000000008bf028b, 0x000000000efa034f,
	0x0000000016a1040d, 0x00000000200004ea,
	0x000000002ae20597, 0x000000003721065c,
	0x000000004507072b, 0x00000000542f07cd,
	0x00000000651208a2, 0x0000000077860970,
	0x000000008b8f0a34, 0x00000000a0d50adf,
	0x00000000b75c0b75, 0x00000000cfa40c5e,
	0x00000000e9440d01, 0x0000000004520db2,
	0x0000000020b10e6e, 0x0000000000000000,
	0x000000000000baf8, 0x000000000000bb06,
	0x000000000000bb20, 0x000000000000bb2e,
	0x000000000000bb3c, 0x000000000000bb50,
	0x000000000000bb6a, 0x000000000000bb7c,
	0x000000000000bb8e, 0x000000000000bba8,
	0x000000000000bbbe, 0x000000000000bbdc,
	0x000000000000bbfc, 0x000000000000bc0a,
	0x000000000000bc26, 0x000000000000bc36,
	0x000000000000bc46, 0x000000000000bc5c
]


already = []

for i in range(len(checksums)):
    for a in range(0x100):
        for b in range(0x100):
            c = zlib.adler32(bytes(already+[a,b]))
            if c == checksums[i]:
                already = already + [a,b]
                print(''.join([chr(c) for c in already]))
```



    >python solve.py
    pb
    pbct
    pbctf{
    pbctf{ac
    pbctf{acKs
    pbctf{acKshu
    pbctf{acKshuaL
    pbctf{acKshuaLLy
    pbctf{acKshuaLLy_p
    pbctf{acKshuaLLy_p0r
    pbctf{acKshuaLLy_p0rta
    pbctf{acKshuaLLy_p0rtabl
    pbctf{acKshuaLLy_p0rtable_
    pbctf{acKshuaLLy_p0rtable_3x
    pbctf{acKshuaLLy_p0rtable_3x3c
    pbctf{acKshuaLLy_p0rtable_3x3cut
    pbctf{acKshuaLLy_p0rtable_3x3cutAb
    pbctf{acKshuaLLy_p0rtable_3x3cutAbLe
    pbctf{acKshuaLLy_p0rtable_3x3cutAbLe?}


# LLLattice

    It seems like there is a UART echoserver design running on a Lattice FPGA. The UART bus runs 8N1 at a rate of 100 clocks per symbol. Can you reverse it and find out what secret it holds?
    Author: VoidMercy
    
LLLattice provides a ECP5 Lattice FPGA bitstream to work with

NOTE: I didn't solve this challenge during the CTF, but I found it very interesting and decided to spent a bit more time on it after
   
## Solution

### Decompilation

Within the header of the binary file the string `LFE5U-25F-6CABGA381` can be found, this is the exact FPGA model for which this bitstream was generated.
With this information further tooling can be found:

- Robert Xiao has a [writeup](https://ubcctf.github.io/2021/06/pwn2win-ethernetfromabove/) for Pwn2Win 2021's `Ethernet from Above` that contains code for ECP5 decompilation (in fact the tooling is also in upstream [prjtrellis](https://github.com/YosysHQ/prjtrellis))

- The challenge author VoidMercy provided mid-ctf an update to [their tool](https://github.com/VoidMercy/Lattice-ECP5-Bitstream-Decompiler) for ECP5 decompilation

After a lot of trying around I decided to use VoidMercy's decompiler and used the following [yosys](https://github.com/YosysHQ/yosys) commands to get [a very good output](chal.v):

```
read_verilog chal.tfg.v
hierarchy -top top
synth
flatten
opt
clean
opt_clean -purge
write_verilog -noattr chal.v
```

### Static Analysis

I then put the simplified Verilog file into Vivado, synthesized it, and did further static analysis on the [RTL Schematic](img/lllattice_schematic.pdf):

![](img/lllattice_overview.png)

Within the overview it is possible seperate the long left part, a big blob in the middle and the right part.

![](img/lllattice_left.png)

The left part mostly contains uninteresting UART decoding logic, but following the traces the 3 inputs can be identified.
`G_HPBX0000` is `CLK`, `MIB_R0C60_PIOT0_JPADDIA_PIO` is `RESET` (and active low) and `MIB_R0C40_PIOT0_JPADDIB_PIO` is `RX` which is inactive when high.


![](img/lllattice_right.png)

The right part is more interesting, as it contains the multiplexer logic to choose which bit from the output buffer to actually output.
The only output is obviously the UART output. The red buffers in the image are the buffers that contain the next byte to output.
The yellow buffers contain the last byte that was input. 

![](img/lllattice_toggle.png)

Interestingly, the output buffer is not directly connected to the input buffer, even though it is meant to be an echo service.
In fact there are multiplexers that either choose the input or something that is computed by the purple area.

![](img/lllattice_middle.png)

Now the most interesting part is the middle. The input is buffered in the dark orange buffers. These connect directly to the yellow buffers.
But they are also connected to weird dark red logic. I assume this is where the password is encoded, which we need to enter to get the flag.
The dark red logic is connected to the blue flipflops, which also connect to the logic where I assumed the flag is encoded.


### Dynamic Analysis

To dynamically work with this program, the first thing I tried to do was to get the promised UART echo service running.

I chose [Verilator](https://www.veripool.org/verilator/) and the [pyverilator](https://github.com/csail-csg/pyverilator) wrapper around it to write my scripts.

Note: No get access to the internal signals using pyverilator, the top module must be named like the file (This wasted more of my time than it should have)
Also newer Verilator version don't work with the current version of pyverilator, I downgraded to 4.020.

![](img/lllattice_serialgraph.png)

(RED: Input Sampling, BLUE: Output Sampling)


Initially I had some problems figuring out in what format the service wants the data and how the timings are, but after a bit of testing and looking at VDD traces which contained a lot of helpful signals to figure out how the data is decoded and encoded, I got the UART interaction to work:

```python
import os
import pyverilator
import random

build_dir = os.path.join(os.path.dirname(__file__), 'build', os.path.basename(__file__))
os.makedirs(build_dir, exist_ok = True)
os.chdir(build_dir)

with open('chal.v', 'w') as out:
    with open('../../chal.v', 'r') as f:
            out.write(f.read())

sim = pyverilator.PyVerilator.build('chal.v')


def tick_clock(datamap=None):
    sim.io.G_HPBX0000 = 0 # CLK = 0
    sim.io.G_HPBX0000 = 1 # CLK = 1
    
def setdata(v):
    sim.io.MIB_R0C40_PIOT0_JPADDIB_PIO = v # TX = v

def readdata():
    return sim.io.MIB_R0C40_PIOT0_PADDOA_PIO # RX
    
def writebyte(d):
    # LOW for one UART tick to indicate sending
    setdata(0)
    for waitfor in range(CLOCK_RATE):
        tick_clock()
    # Send data bit for bit
    for b in range(8):
        setdata((d >> b) & 1)
        for waitfor in range(CLOCK_RATE):
            tick_clock()
    # HIGH for two UART ticks to process data
    setdata(1)
    for waitfor in range(CLOCK_RATE):
        tick_clock()

    
def readbyte():
    c = 0
    # receive data bit for bit
    for x in range(8):
        for waitfor in range(CLOCK_RATE):
            tick_clock()
        c = (readdata()<<x) | c
    return c
    
CLOCK_RATE = 100 # as description says, 100 clock ticks per symbol

# reset
setdata(1)
sim.io.MIB_R0C60_PIOT0_JPADDIA_PIO = 0
for waitfor in range(CLOCK_RATE):
    tick_clock()
sim.io.MIB_R0C60_PIOT0_JPADDIA_PIO = 1

while True:
    texttosend = input("< ")
    if texttosend == "": texttosend = "\x00"
    textreceived = ""
    for chartosend in texttosend:
        writebyte(ord(chartosend))
        datareceived = readbyte()
        textreceived = textreceived + chr(datareceived)
    print("> "+textreceived)
```

```
< Ping
> Ping
< Pong
> Pong
<
```


Now as annotated in the Schematic Graph I grouped the flipflops together to read their value during runtime:

```python
# red block = output buffer
redBlock = 0
redBlock = redBlock | (sim.internals["R3C38_PLC2_inst.sliceC_inst.ff_1.Q"]<<0)
redBlock = redBlock | (sim.internals["R5C38_PLC2_inst.sliceA_inst.ff_1.Q"]<<1)
redBlock = redBlock | (sim.internals["R3C38_PLC2_inst.sliceB_inst.ff_0.Q"]<<2)
redBlock = redBlock | (sim.internals["R3C40_PLC2_inst.sliceA_inst.ff_0.Q"]<<3)
redBlock = redBlock | (sim.internals["R3C38_PLC2_inst.sliceD_inst.ff_0.Q"]<<4)
redBlock = redBlock | (sim.internals["R5C38_PLC2_inst.sliceB_inst.ff_0.Q"]<<5) 
redBlock = redBlock | (sim.internals["R3C38_PLC2_inst.sliceA_inst.ff_0.Q"]<<6) 
redBlock = redBlock | (sim.internals["R3C40_PLC2_inst.sliceD_inst.ff_0.Q"]<<7)


# yellow block = normal output / echo
yellowBlock = 0
yellowBlock = yellowBlock | (sim.internals["R2C39_PLC2_inst.sliceD_inst.ff_0.Q"]<<0)
yellowBlock = yellowBlock | (sim.internals["R5C40_PLC2_inst.sliceD_inst.ff_0.Q"]<<1)
yellowBlock = yellowBlock | (sim.internals["R2C40_PLC2_inst.sliceB_inst.ff_0.Q"]<<2)
yellowBlock = yellowBlock | (sim.internals["R2C42_PLC2_inst.sliceB_inst.ff_0.Q"]<<3)
yellowBlock = yellowBlock | (sim.internals["R4C39_PLC2_inst.sliceC_inst.ff_0.Q"]<<4)
yellowBlock = yellowBlock | (sim.internals["R6C39_PLC2_inst.sliceD_inst.ff_0.Q"]<<5)
yellowBlock = yellowBlock | (sim.internals["R4C40_PLC2_inst.sliceD_inst.ff_0.Q"]<<6)
yellowBlock = yellowBlock | (sim.internals["R5C39_PLC2_inst.sliceD_inst.ff_0.Q"]<<7)

# interesting comparison results
blueBlock = 0
blueBlock = blueBlock | (sim.internals["R3C41_PLC2_inst.sliceB_inst.ff_1.Q"]<<0)
blueBlock = blueBlock | (sim.internals["R4C43_PLC2_inst.sliceC_inst.ff_0.Q"]<<1)
blueBlock = blueBlock | (sim.internals["R4C41_PLC2_inst.sliceC_inst.ff_0.Q"]<<2)
blueBlock = blueBlock | (sim.internals["R6C43_PLC2_inst.sliceA_inst.ff_0.Q"]<<3)
blueBlock = blueBlock | (sim.internals["R4C42_PLC2_inst.sliceC_inst.ff_0.Q"]<<4)
blueBlock = blueBlock | (sim.internals["R3C42_PLC2_inst.sliceB_inst.ff_1.Q"]<<5)
```

The bits of the red-block and yellow-block are sorted to match up with the input encoding.
For the blue-block I'm not completely sure what each bit means, but after bruteforcing the first character through testing all 256 inputs, I noticed that for only one the bits change:

```
0x76 (Input) => 0x76 (Yellow) => 0x76 (Red) | "v" (Character)
01110110( Input) => 01110110 (Output) | Blue: 00000010
```


### Password Bruteforce

As assumed during static analysis these flipflops are indeed very interesting!
With a small [solve script](solve_lattice.py) I then bruteforced each password character individually.
After the password is entered, the service outputs the flag to us:

```
0x76 => 0x76 => 0x76 | v
01110110 => 01110110 | B: 00000010
>v
0x33 => 0x33 => 0x76 | 3
00110011 => 11111111 | B: 00001000
>v3
0x72 => 0x72 => 0x72 | r
01110010 => 01110010 | B: 00001010
>v3r
0x69 => 0x69 => 0x72 | i
01101001 => 11111111 | B: 00000001
>v3ri
0x6c => 0x6c => 0x6c | l
01101100 => 01101100 | B: 00000011
>v3ril
0x30 => 0x30 => 0x6c | 0
00110000 => 11111111 | B: 00001001
>v3ril0
0x67 => 0x67 => 0x67 | g
01100111 => 01100111 | B: 00001011
>v3ril0g
0x5f => 0x5f => 0x67 | _
01011111 => 11111111 | B: 00000100
>v3ril0g_
0x31 => 0x31 => 0x31 | 1
00110001 => 00110001 | B: 00000110
>v3ril0g_1
0x73 => 0x73 => 0x31 | s
01110011 => 11111111 | B: 00001100
>v3ril0g_1s
0x5f => 0x5f => 0x5f | _
01011111 => 01011111 | B: 00001110
>v3ril0g_1s_
0x70 => 0x70 => 0x5f | p
01110000 => 11111111 | B: 00000101
>v3ril0g_1s_p
0x61 => 0x61 => 0x61 | a
01100001 => 01100001 | B: 00000111
>v3ril0g_1s_pa
0x69 => 0x69 => 0x61 | i
01101001 => 11111111 | B: 00001101
>v3ril0g_1s_pai
0x6e => 0x6e => 0x6e | n
01101110 => 01101110 | B: 00001111
>v3ril0g_1s_pain
0x5f => 0x5f => 0x6e | _
01011111 => 11111111 | B: 00100000
>v3ril0g_1s_pain_
0x70 => 0x70 => 0x70 | p
01110000 => 01110000 | B: 00100010
>v3ril0g_1s_pain_p
0x65 => 0x65 => 0x70 | e
01100101 => 11111111 | B: 00101000
>v3ril0g_1s_pain_pe
0x6b => 0x6b => 0x6b | k
01101011 => 01101011 | B: 00101010
>v3ril0g_1s_pain_pek
0x6f => 0x6f => 0x0 | o
01101111 => 00000000 | B: 00100001
>v3ril0g_1s_pain_peko
>
>b
>bc
>bct
>bctf
>bctf{
>bctf{h
>bctf{h4
>bctf{h4r
>bctf{h4rd
>bctf{h4rdw
>bctf{h4rdwa
>bctf{h4rdwar
>bctf{h4rdware
>bctf{h4rdware_
>bctf{h4rdware_b
>bctf{h4rdware_ba
>bctf{h4rdware_bac
>bctf{h4rdware_back
>bctf{h4rdware_backd
>bctf{h4rdware_backd0
>bctf{h4rdware_backd00
>bctf{h4rdware_backd00r
>bctf{h4rdware_backd00rs
>bctf{h4rdware_backd00rs_
>bctf{h4rdware_backd00rs_4
>bctf{h4rdware_backd00rs_4r
>bctf{h4rdware_backd00rs_4r3
>bctf{h4rdware_backd00rs_4r3_
>bctf{h4rdware_backd00rs_4r3_v
>bctf{h4rdware_backd00rs_4r3_ve
>bctf{h4rdware_backd00rs_4r3_ver
>bctf{h4rdware_backd00rs_4r3_very
>bctf{h4rdware_backd00rs_4r3_very_
>bctf{h4rdware_backd00rs_4r3_very_f
>bctf{h4rdware_backd00rs_4r3_very_fu
>bctf{h4rdware_backd00rs_4r3_very_fun
>bctf{h4rdware_backd00rs_4r3_very_fun!
>bctf{h4rdware_backd00rs_4r3_very_fun!}
Done...
```

And to confirm let's do it directly per UART as well:

```
< v3ril0g_1s_pain_peko
> v3ril0g_1s_pain_peko
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
> pbctf{hrdware_bacd00rs_4r3_vry_fun!}
```