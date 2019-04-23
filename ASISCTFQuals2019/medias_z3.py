from z3 import *

s = Solver()

variableSizeFactor = 8 # adjusting number to multiply with 3 until no found

arg1Size = 3*variableSizeFactor 
arg1SizeM = (arg1Size/3)

argv1 = IntVector("argv1", arg1Size) # an array holding all of the digits
val = Int("val") # the value of the digits interpreted as a single number

row1 = Int("row1") # the first third
row2 = Int("row2") # the second third
row3 = Int("row3") # the last third

s.add(arg1Size%3 == 0) # check if the length is matching the constraints

for i in range(arg1Size): # verify that the digit array only contains single digits
    s.add(argv1[i] >= 0)
    s.add(argv1[i] < 10)
 
# Set the digits together to form the integer values
s.add(val == Sum([argv1[index]*(10**(arg1Size-1-index)) for index in range(arg1Size)]))
s.add(row1 == Sum([argv1[index]*(10**(arg1SizeM-1-index)) for index in range(arg1SizeM)]))
s.add(row2 == Sum([argv1[index+arg1Size/3]*(10**(arg1SizeM-1-index)) for index in range(arg1SizeM)]))
s.add(row3 == Sum([argv1[index+arg1Size/3*2]*(10**(arg1SizeM-1-index)) for index in range(arg1SizeM)]))

# these constraints are checked on the three parts
for i in range(1,arg1SizeM-1):
    s.add(argv1[i-1] != 0)
    s.add(2*argv1[i] - argv1[i-1] < argv1[i+1])
    s.add(argv1[(i-1)+arg1Size/3] != 0)
    s.add(2*argv1[i+arg1Size/3] - argv1[(i-1)+arg1Size/3] < argv1[(i+1)+arg1Size/3])
    s.add(argv1[(i-1)+arg1Size/3*2] != 0)
    s.add(2*argv1[i+arg1Size/3*2] - argv1[(i-1)+arg1Size/3*2] < argv1[(i+1)+arg1Size/3*2])

# the last check done on the numbers
s.add(10**6 + row1 <= 10**5 + row2)
s.add(10**5 + row2 <= 10**4 + row3)

while s.check():
    m = s.model()
    print(m[val].as_long()) # try out last found number
    s.add(val > m[val].as_long()) # find all numbers until no are left