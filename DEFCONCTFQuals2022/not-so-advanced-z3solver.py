from z3 import *


flagString = [BitVec('c'+str(i), 8) for i in range(9)]

solver = Solver()

# guessed
def weirdFun(a, b):
    return a % b

# Input is a-z or _
for i in range(9):
    solver.add(Or(And(flagString[i] >= ord('a'), flagString[i] <= ord('z')), flagString[i] == ord('_')))

v12 = 1
v14 = 0
for i in range(9):
    v12 = weirdFun(v12 + ZeroExt(32, flagString[i]), 0xfff1)
    v14 = weirdFun(v14 + v12, 0xfff1)

solver.add((v14^v12)&0xffff == 0x12e1)

print(solver.check())
m = solver.model()

s = ""
for i in range(9):
    s += (chr(m[flagString[i]].as_long()))
    
print(s)