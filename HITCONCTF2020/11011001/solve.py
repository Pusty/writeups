from z3 import *
import math

s = Solver()

inputBuffer = [BitVec("inp_"+str(i), 32) for i in range(20)]

compareData = [0x81002, 0x1000, 0x29065, 0x29061,
               0, 0, 0x16C40, 0x16C00,
               0x20905, 0x805, 0x10220, 0x220,
               0x98868, 0x80860, 0x21102, 0x21000,
               0x491, 0x481, 0x31140, 0x1000,
               0x801, 0x0, 0x60405, 0x400,
               0x0C860, 0x60, 0x508, 0x400, 
               0x40900, 0x800, 0x12213, 0x10003,
               0x428C0, 0x840, 0x840C, 0x0C,
               0x43500, 0x2000, 0x8105A,0x1000]
               
for index in range(20):
    s.add((compareData[2 * index] & inputBuffer[index]) == compareData[2 * index + 1])
    
    
for index in range(20):
    for shift in range(18):
        s.add(((inputBuffer[index] >> shift) & 7) != 7)
        s.add(((inputBuffer[index] >> shift) & 7) != 0)


for shiftIndex in range(20):
    orValue = 0
    for index in range(20):
        shiftedValue = inputBuffer[index] >> shiftIndex;
        orValue = ((shiftedValue & 1) << index) | orValue;
        
    for shift in range(18):
        s.add(((orValue >> shift) & 7) != 7)
        s.add(((orValue >> shift) & 7) != 0)
        
        
def popcount(bvec): # Hamming Weight
    return Sum([ ZeroExt(int(math.ceil(math.log(bvec.size(), 2.0))), Extract(i,i,bvec)) for i in range(bvec.size())])
  
for index in range(20):
    s.add(popcount(inputBuffer[index]) == 10)
    
for shiftIndex in range(20):
    orValue = 0
    for index in range(20):
        shiftedValue = inputBuffer[index] >> shiftIndex;
        orValue = ((shiftedValue & 1) << index) | orValue;
      
    s.add(popcount(orValue) == 10)
    
s.add(Distinct(inputBuffer))


for untilValue in range(19):
    for innerValue in range(untilValue):
        orValue = 0
        for index in range(20):
            shiftedValue = inputBuffer[index] >> untilValue;
            orValue = ((shiftedValue & 1) << index) | orValue;
        orValue2 = 0
        for index in range(20):
            shiftedValue2 = inputBuffer[index] >> innerValue;
            orValue2 = ((shiftedValue2 & 1) << index) | orValue2;
        
        s.add(orValue != orValue2)
        
print(s.check())
m = s.model()

print(m)

for i in range(20):
    print(str(m[inputBuffer[i]]))

"""
[inp_4 = 629333,
 inp_10 = 676716,
 inp_16 = 183638,
 inp_6 = 682342,
 inp_8 = 370089,
 inp_0 = 350617,
 inp_11 = 634010,
 inp_17 = 864940,
 inp_19 = 447908,
 inp_2 = 828630,
 inp_3 = 224554,
 inp_12 = 340837,
 inp_13 = 412886,
 inp_5 = 304811,
 inp_7 = 742996,
 inp_9 = 318099,
 inp_1 = 693097,
 inp_15 = 349483,
 inp_18 = 731731,
 inp_14 = 699033]
"""