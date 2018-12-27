from z3 import *

for amount in range(1,32):
    print amount
    s = []
    for i in range(32):
        s.append(BitVec('s['+str(i)+']',17))
        
    base = BitVec('base',17)
        
        
    bV = (0x800*amount+0x400*amount)&0xFFFF

    print hex(bV +0x20*amount)
    print hex(bV +0x70*amount)
     
    solver = Solver()
    for i in range(len(s)):
        solver.add(s[i] >= 0x0)
        if i == amount:
            solver.add(s[i] == 0x20)
        else:
            solver.add(s[i] != 0x20)
        solver.add(s[i] < 0x7F-0x20)
        
    solver.add(((Sum([s[i]+0x20 for i in range(amount)])&0xFFFF)+((0x800*amount+0x400*amount)&0xFFFF))&0xFFFF == base)
    solver.add(0xFC7F ==  ((base&0xFFFF)+((((s[1]*128)&0xFFFF)+s[0]))&0xFFFF))
    solver.add(0xF30F ==  ((base&0xFFFF)+((((s[3]*128)&0xFFFF)+(s[2]))^0x21))&0xFFFF) #
    solver.add(0xF361 ==  ((base&0xFFFF)+((((s[5]*128)&0xFFFF)+(s[4]))^0x42))&0xFFFF) #
    solver.add(0xF151 ==  ((base&0xFFFF)+((((s[7]*128)&0xFFFF)+(s[6]))^0x63))&0xFFFF) #
    solver.add(0xF886 ==  ((base&0xFFFF)+((((s[9]*128)&0xFFFF)+(s[8]))^0x84))&0xFFFF) #
    solver.add(0xF3D1 ==  ((base&0xFFFF)+((((s[11]*128)&0xFFFF)+(s[10]))^0xA5))&0xFFFF)
    solver.add(0xDB57 ==  ((base&0xFFFF)+((((s[13]*128)&0xFFFF)+(s[12]))^0xC6))&0xFFFF) #
    solver.add(0xD9D5 ==  ((base&0xFFFF)+((((s[15]*128)&0xFFFF)+(s[14]))^0xE7))&0xFFFF)
    solver.add(0xE26E ==  ((base&0xFFFF)+((((s[17]*128)&0xFFFF)+(s[16]))^0x108))&0xFFFF)
    solver.add(0xF8CD ==  ((base&0xFFFF)+((((s[19]*128)&0xFFFF)+(s[18]))^0x129))&0xFFFF)
    solver.add(0xF969 ==  ((base&0xFFFF)+((((s[21]*128)&0xFFFF)+(s[20]))^0x14A))&0xFFFF)
    solver.add(0xD90C ==  ((base&0xFFFF)+((((s[23]*128)&0xFFFF)+(s[22]))^0x16B))&0xFFFF)
    solver.add(0xF821 ==  ((base&0xFFFF)+((((s[25]*128)&0xFFFF)+(s[24]))^0x18C))&0xFFFF)
    solver.add(0xF181 ==  ((base&0xFFFF)+((((s[27]*128)&0xFFFF)+(s[26]))^0x1AD))&0xFFFF)
    solver.add(0xF85F ==  ((base&0xFFFF)+((((s[29]*128)&0xFFFF)+(s[28]))^0x1CE))&0xFFFF) #
    
    while str(solver.check()) == "sat":
        m = solver.model()
        r = ""
        for i in range(len(s)):
            r += chr((m[s[i]].as_long()+0x20)&0xFF)
        r += " "
        r += hex(m[base].as_long())
        r += " "
        r += hex((0x800*amount+0x400*amount)&0xFFFF)
        r += " "
        r += hex(((m[s[0]].as_long())*128+(m[s[1]].as_long())))
        r += " "
        r += hex(((m[s[3]].as_long())*128+(m[s[2]].as_long()^0x21)))
        r += " "
        r += hex(((m[s[5]].as_long())*128+(m[s[4]].as_long()^0x42)))
        print r
        solver.add(Or(s[0]!=m[s[0]],s[1]!=m[s[1]],s[2]!=m[s[2]],s[3]!=m[s[3]]))