def dec(v):
    return v-1
    
def inc(v):
    if v == 0x4268: return v
    return v+1

def k91e(a):
    if(a[0] == 0 or a[4] == 0): return;
    a[0] = dec(a[0]);
    a[4] = dec(a[4]);
    a[6] = inc(a[6]);
    
def k852(a):
    if(a[4] == 0 or a[6] == 0): return;
    a[4] = dec(a[4]);
    a[6] = dec(a[6]);
    a[2] = inc(a[2]);
    
def k8a2(a):
    if(a[2] == 0 or a[4] == 0 or a[6] == 0): return;
    a[2] = dec(a[2]);
    a[4] = dec(a[4]);
    a[6] = dec(a[6]);
    a[1] = inc(a[1]);
    
def k8a3(a):
    if(a[0] == 0 or a[3] == 0): return;
    a[0] = dec(a[0]);
    a[3] = dec(a[3]);
    a[4] = inc(a[4]);
    
def k899(a):
    if(a[0] == 0 or a[6] == 0): return;
    a[0] = dec(a[0]);
    a[6] = dec(a[6]);
    a[3] = inc(a[3]);
    
def k917(a):
    if(a[2] == 0 or a[3] == 0): return;
    a[2] = dec(a[2]);
    a[3] = dec(a[3]);
    a[1] = inc(a[1]); 
    
def k86c(a):
    if(a[0] == 0 or a[4] == 0): return;
    a[0] = dec(a[0]);
    a[4] = dec(a[4]);
    a[5] = inc(a[5]);
    
def k933(a):
    if(a[0] == 0 or a[6] == 0): return;
    a[0] = dec(a[0]);
    a[6] = dec(a[6]);
    a[5] = inc(a[5]);
    
def k93a(a):
    if(a[0] == 0 or a[4] == 0): return;
    a[0] = dec(a[0]);
    a[4] = dec(a[4]);
    a[5] = inc(a[5]);
    
startArray = [
0x0000000000000734,
0x0000000000000000,
0x0000000000000000,
0x0000000000000000,
0x0000000000000bbc,
0x0000000000000000,
0x0000000000000b63
]

cmpArray = [
0x000000000000014d,
0x00000000000002d7,
0x0000000000000161,
0x00000000000002ea,
0x00000000000001b1,
0x00000000000002fd,
0x0000000000000169
]


print("Initial Attempt")

a = startArray+[]

k933(a) # start of function

for i in range(746):
    k899(a) # call function
    
for i in range(353):
    k852(a) # store value

for i in range(727):
    k8a2(a) # throw number
    k852(a) # store to compensate

for i in range(763):
    k86c(a) # return values

k93a(a) # end of function


for x in range(len(startArray)):
    print(x, hex(a[x]), "(", hex(startArray[x]), ")", "==", hex(cmpArray[x]), "|" , a[x] == cmpArray[x])
    


print("Working solution")

a = startArray+[]

k933(a) # start of function

for i in range(746-727):
    k899(a) # calls
    
for i in range(353):
    k852(a) # stores
    
# these are all generates by "throw <number>;"
for i in range(727):
    k852(a) # store 
    k899(a) # call
    k8a2(a) # throw number
    k93a(a) # end of function
    

for i in range(763-727):
    k86c(a) # return values 

k93a(a) # end of function

for x in range(len(startArray)):
    print(x, hex(a[x]), "(", hex(startArray[x]), ")", "==", hex(cmpArray[x]), "|" , a[x] == cmpArray[x])
    

print("==================================")

print("void extr();")
print("int funcT(int v) {")

for i in range(746-727):
    print("extr();") 
    
for i in range(353):
    print("v = 1337;")

for i in range(727):
    print("throw 420;") # this includes the stores, call and end of function

for i in range(763-727):
    print("return 123;")
    
print("}")

    
"""
from z3 import *


v91e = Int("v91e_catch")
v852 = Int("v852_store")
v8a3 = Int("v8a3_specialbranch")
v899 = Int("v899_call")
v917 = Int("v917_newthrow")
v86c = Int("v86c_return")
v933 = Int("v933_entry")
v93a = Int("v93a_pragma")

a = [startArray[x] for x in range(len(startArray))]


a[0] = a[0] - v91e
a[4] = a[4] - v91e
a[6] = a[6] + v91e
#for i in range(len(a)):
#    a[i] = If(a[i] < 0, 0, a[i])
#    a[i] = If(a[i] > 0x4268, 0x4268, a[i])
a[4] = a[4] - v852
a[6] = a[6] - v852
a[2] = a[2] + v852
#for i in range(len(a)):
#    a[i] = If(a[i] < 0, 0, a[i])
#    a[i] = If(a[i] > 0x4268, 0x4268, a[i])
a[0] = a[0] - v8a3
a[3] = a[3] - v8a3
a[4] = a[4] + v8a3
#for i in range(len(a)):
#    a[i] = If(a[i] < 0, 0, a[i])
#    a[i] = If(a[i] > 0x4268, 0x4268, a[i])
a[0] = a[0] - v899
a[6] = a[6] - v899
a[3] = a[3] + v899
#for i in range(len(a)):
#    a[i] = If(a[i] < 0, 0, a[i])
#    a[i] = If(a[i] > 0x4268, 0x4268, a[i])
a[2] = a[2] - v917
a[3] = a[3] - v917
a[1] = a[1] + v917
#for i in range(len(a)):
#    a[i] = If(a[i] < 0, 0, a[i])
#    a[i] = If(a[i] > 0x4268, 0x4268, a[i])
a[0] = a[0] - v86c
a[4] = a[4] - v86c
a[5] = a[5] + v86c
#for i in range(len(a)):
#    a[i] = If(a[i] < 0, 0, a[i])
#    a[i] = If(a[i] > 0x4268, 0x4268, a[i])
a[0] = a[0] - v933
a[6] = a[6] - v933
a[5] = a[5] + v933
#for i in range(len(a)):
#    a[i] = If(a[i] < 0, 0, a[i])
#    a[i] = If(a[i] > 0x4268, 0x4268, a[i])
a[0] = a[0] - v93a
a[4] = a[4] - v93a
a[5] = a[5] + v93a
#for i in range(len(a)):
#    a[i] = If(a[i] < 0, 0, a[i])
#    a[i] = If(a[i] > 0x4268, 0x4268, a[i])

s = Optimize()
for x in range(len(cmpArray)):
    s.add(a[x] == cmpArray[x])


s.add(v91e >= 0)
s.add(v852 >= 0)
s.add(v8a3 >= 0)
s.add(v899 >= 0)
s.add(v917 >= 0)
s.add(v86c >= 0)
s.add(v933 >= 0)
s.add(v93a >= 0)

#s.add(v917 == 0)

#s.add(v93a == v91e * 2 + 1)
#s.add(v8a3 == v91e)

#s.minimize(v933) 
#s.minimize(v8a3) 
#s.minimize(v86c) 


print(s.check())
m = s.model()
print(m)
"""