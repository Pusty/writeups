from z3 import *
    
s = Solver()

# sub_40140a

length = 9
len2 = length+2
flag = []
for i in range(length):
    flag.append(BitVec('flag['+str(i)+"]",64))
    s.add(flag[i] >= 0)
    s.add(flag[i] < 10)
    

v7 = BitVec('v7',64)
v6 = BitVec('v6',64)
v5 = BitVec('v5',64)
v4 = BitVec('v4',64)

s.add(flag[4] == 1)
s.add(v7 == Sum([flag[i]*(10**(length-i-1)) for i in range(length)]))
s.add(v7 % len2 == 0)
s.add(v6 == v7 / 100000)
s.add(v5 == v7 % 10000)


s.add(10 * (v7 % 10000 / 1000) + v7 % 10000 % 100 / 10 - (10 * (v7 / 100000 / 1000) + v7 / 100000 % 10) == 1)
s.add(10 * (v6 / 100 % 10) + v6 / 10 % 10 - 2 * (10 * (v5 % 100 / 10) + v5 % 1000 / 100) == 8)

s.add(v4 == 10 * (v5 / 100 % 10) + v5 % 10)
s.add((10 * (v6 % 10) + v6 / 100 % 10) / v4 == 3)
s.add(((10 * (v6 % 10) + v6 / 100 % 10) % v4) == 0)

s.add(v7%(v5*v6) == len2*len2*len2 + 6)

while s.check():
    m = s.model()
    print(''.join( [str(m[flag[i]].as_long()).replace("L","") for i in range(length)]))
    s.add(v7 != m[v7])
    
# 790317143