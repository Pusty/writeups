from z3 import *
import ctypes

# manual translation of the decompilation
def quick_maths(arg1):
    r3_15 = UDiv(UDiv((arg1 + 0x1dd9), 6) - 0x189, 0xf)
    r3_23 = r3_15 - 0x1f7 + r3_15 - 0x1f7
    r3_24 = r3_23 + r3_23
    r3_25 = r3_24 + r3_24
    r3_26 = r3_25 + r3_25
    r3_33 = (r3_26 + r3_26 + 0x249a) ^ 0x2037841a
    return LShR(((0 - r3_33) | r3_33) ^ 0xffffffff, 0x1f)&0xFF
    
arg1 = BitVec("arg1", 32)

s = Solver()

# solve for the bit to be set
s.add(quick_maths(arg1)&1 == 1)

# check if the model is sat
print(s.check())

# convert the number to a 32bit signed integer
vl = s.model()[arg1].as_long()&0xffffffff
print(ctypes.c_long(vl).value)