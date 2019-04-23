from z3 import *
    
s = Solver()

# sub_1fca

length = 19
lengthP3 = length*length*length

flag = []
for i in range(length):
    flag.append(BitVec('flag['+str(i)+"]",64))
    s.add(flag[i] >= 0)
    s.add(flag[i] < 10)
    
haystack = []
for i in range(5):
    haystack.append(BitVec('haystack['+str(i)+"]",64))
    s.add(haystack[i] == flag[length-5+i])
    
s.add(Or(And(haystack[0]==1, haystack[1]==3, haystack[2]==3, haystack[3] == 7),And(haystack[1]==1, haystack[2]==3, haystack[3]==3, haystack[4] == 7)))

v1 = BitVec('v1',64)
v2 = BitVec('v2',64)

s.add(v1 == Sum([haystack[i]*(10**(5-i-1)) for i in range(5)]))
s.add(v2 == 100*flag[13] + 1000*flag[6] + flag[15])
s.add(v1%lengthP3 == v2)

needle = []
for i in range(4):
    needle.append(BitVec('needle['+str(i)+"]",64))
    s.add(needle[i] == haystack[i+1])
    
orList = []
for i in range(15-4):
    orList.append(And(flag[i] == needle[0], flag[i+1] == needle[1], flag[i+2] == needle[2], flag[i+3] == needle[3]))
s.add(Or(orList))

s.add(flag[0] == flag[length-8])
s.add(flag[length-2] +flag[length-3] + flag[length-4] + 1 == flag[1])
s.add(length % 19 == 0)

val = BitVec("val", 64)
s.add(val == Sum([flag[index]*(10**(length-1-index)) for index in range(length)]))

while s.check():
    m = s.model()
    print(m[val].as_long())
    s.add(val != m[val])
    
"""
7812133711170931337
3800053001337931337
3820053001337931337
3827053001337931337
7813373000877931337
7813373008877931337
849113374600931337
3800003091337931337
...
"""