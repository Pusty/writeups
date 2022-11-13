# Devil Hunter 

    Clam Devil; Asari no Akuma
    
The binary provides a ClamAV Bytecode file and a script to run it to scan a file.

## Solution

The ClamAV Bytecode file is in a bianry format so the first step is to get the source bytecode.

Normally you would use the `printsrc` flag for this:
```
# clambc --printsrc flag.cbc
not so easy :P
```

But that sadly doesn't work

Getting the IR instead works:
```
# clambc --printbcir flag.cbc > flag.txt
```

So now instead we have 3 functions in a format like this:

```
########################################################################
####################### Function id   0 ################################
########################################################################
found a total of 4 globals
GID  ID    VALUE
------------------------------------------------------------------------
  0 [  0]: i0 unknown
  1 [  1]: [22 x i8] unknown
  2 [  2]: i8* unknown
  3 [  3]: i8* unknown
------------------------------------------------------------------------
found 2 values with 0 arguments and 2 locals
VID  ID    VALUE
------------------------------------------------------------------------
  0 [  0]: i1
  1 [  1]: i32
------------------------------------------------------------------------
found a total of 2 constants
CID  ID    VALUE
------------------------------------------------------------------------
  0 [  2]: 21(0x15)
  1 [  3]: 0(0x0)
------------------------------------------------------------------------
found a total of 4 total values
------------------------------------------------------------------------
FUNCTION ID: F.0 -> NUMINSTS 5
BB   IDX  OPCODE              [ID /IID/MOD]  INST
------------------------------------------------------------------------
  0    0  OP_BC_CALL_DIRECT   [32 /160/  0]  0 = call F.1 ()
  0    1  OP_BC_BRANCH        [17 / 85/  0]  br 0 ? bb.1 : bb.2

  1    2  OP_BC_CALL_API      [33 /168/  3]  1 = setvirusname[4] (p.-2147483645, 2)
  1    3  OP_BC_JMP           [18 / 90/  0]  jmp bb.2

  2    4  OP_BC_RET           [19 / 98/  3]  ret 3
------------------------------------------------------------------------
```

Using the [bytecode interpreter](https://github.com/Cisco-Talos/clamav/blob/main/libclamav/bytecode.c) as a reference a manual decompilation looks like this:

```
F.0 () {
    if(F.1()) {
        setvirusname[4] (p.-2147483645, 21)
    }
}

F.2 (val) {
    out = 0xacab3c0
    for(i=0;i<4;i++) {
        tmp = (val >> (i * 8))&0xff
        xorres = (tmp ^ out) 
        out = ((xorres<< 8) | (out >> 24)) & 0xffffffff
    }
    return out
}
```

`F.1` is quite a lot larger so instead of a decompilation a description of it:
    - it first reads data into 4 byte blocks
    - then it loops over them, applies F.2 on the 32-bit integers and stores the result
    - the stored result is compared against a list of values (0x739e80a2, 0x3aae80a3, 0x3ba4e79f, 0x78bac1f3, 0x5ef9c1f3, 0x3bb9ec9f, 0x558683f4, 0x55fad594, 0x6cbfdd9f)

It does some more things and this is not enough for the detection to work but it is enough to get the flag:

```python
import numba

# F.2 implementation
@numba.jit(nopython=True)
def F2(reg0):
    reg1 = 0xacab3c0
    for reg2 in range(4):
        reg8 = (reg0 >> (reg2 * 8))&0xff
        reg11 = (reg8 ^ reg1) 
        
        reg13 = (reg11<< 8) | (reg1 >> 24)
        reg1 = reg13 & 0xffffffff
    return reg1

# invert F.2 by bruteforce
@numba.jit(nopython=True)
def F2Inv(v):
    for i in range(0xffffffff):
        if(F2(i) == v):
            return i
    return -1

# compare constants
array = [0x739e80a2, 0x3aae80a3, 0x3ba4e79f, 0x78bac1f3, 0x5ef9c1f3, 0x3bb9ec9f, 0x558683f4, 0x55fad594, 0x6cbfdd9f]
output = b''
for a in array:
    v = F2Inv(a)
    output += v.to_bytes(4, byteorder='little')
    
print(output)
```

By bruteforcing the value for which the output matches the array entries we get the flag: `byT3c0d3_1nT3rpr3T3r_1s_4_L0T_0f_fun` (which we then wrap in in the flag format to `SECCON{byT3c0d3_1nT3rpr3T3r_1s_4_L0T_0f_fun}`).