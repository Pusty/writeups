from z3 import *

BITNESS = 32

def hash_char(i):
    return If(
        (i-48)&0xFF <= 9, 
        (i-48)&0xFF,
        If((i-65)&0xFF <= 0x19,
            (i-55)&0xFF, 
            If((i-97)&0xFF <= 0x19, 
                (i-61)&0xFF, 
                If(i == 123, 
                    BitVecVal(62, BITNESS),
                    If(i == 125,
                        BitVecVal(63, BITNESS),
                        BitVecVal(0, BITNESS))))))
    
def xor_both_hashes(h, b):
    return [ h[i] ^ b[i%30] for i in range(len(h)) ]
     

def shuffle_str(h):
    sh = [4, 18, 1, 25, 2, 9, 13, 20, 19, 16, 11, 7, 0, 24, 27, 6, 15, 28, 26, 12, 14, 3, 5, 8, 17, 23, 22, 10, 21, 29]
    return [ h[sh.index(i)] for i in range(len(h)) ]
    
    

def swapchars(h):
    o = [h[i] for i in range(len(h))]
    i = 0
    while i < len(h)-1:
        if i != 28 and i != 27:
            p = o[i+1]
            o[i+1] = o[i]
            o[i] = p
        i = i + 3
    return o

def fyrkantignative(h):
    bytes = [0x1F, 0x23, 0x3F, 0x3F, 0x1B, 0x07, 0x37, 0x21, 0x04, 0x33, 0x09, 0x3B, 0x39, 0x28, 0x30, 0x0C, 0x0E, 0x2E, 0x3F, 0x25, 0x2A, 0x27, 0x3E, 0x0B, 0x27, 0x1C, 0x38, 0x31, 0x1E, 0x3D]
    o = xor_both_hashes(h, bytes)
    o = shuffle_str(o)
    o = swapchars(o)
    # somewhere in the swapping is a mistake and this fixes it...
    p = o[28]
    o[28] = o[22]
    o[22] = p
    
    return o


def nativeGRUNDTAL_NORRVIKEN(h):
    return [ hash_char(h[i]) for i in range(len(h)) ]
    

def SMORBOLLp(h):
    num = 16
    for i in range(len(h)):
        if i != len(h)-2:
            m = 1
            if i % 2 == 0:
                m = m + 1
            if i % 3 == 0:
                m = m - 2
            if i % 5 == 0:
                m = m - 3
            if i % 7 == 0:
                m = m + 4
                
            print("h["+str(i)+"] * "+str(m)+"+ ")
    print("16")


def SMORBOLL(h):
    return (h[0] * 1+h[1] * 1+h[2] * 2+h[3] * -1+h[4] * 2+h[5] * -2+h[6] * 0+h[7] * 5+h[8] * 2+h[9] * -1+h[10] * -1+h[11] * 1+h[12] * 0+h[13] * 1+h[14] * 6+h[15] * -4+h[16] * 2+h[17] * 1+h[18] * 0+h[19] * 1+h[20] * -1+h[21] * 3+h[22] * 2+h[23] * 1+h[24] * 0+h[25] * -2+h[26] * 2+h[27] * -1+h[29] * 1+16)
    
solver = Solver()

flag = "CTF{aaaaaaaaaaaaaaaaaaaaaaaaa}" # ^zwy}RKIDZo@F\PmVXYQfDejO_hF@

inputString = [BitVec("c"+str(i), BITNESS) for i in range(len(flag))]

outputString = [BitVec("o"+str(i), BITNESS) for i in range(len(inputString))]

out = fyrkantignative(nativeGRUNDTAL_NORRVIKEN(inputString))

#print(out)
SMORBOLLp(flag)

for i in range(len(flag)):
    solver.add(Or(And(inputString[i] > 47, inputString[i] < 58), # numbers
                  And(inputString[i] > 64, inputString[i] < 91),
                  And(inputString[i] > 96, inputString[i] < 123),
                  inputString[i] == ord('{'),
                  inputString[i] == ord('}')
               ))
    
    solver.add(outputString[i] == out[i])
    
solver.add(inputString[0] == ord('C'))
solver.add(inputString[1] == ord('T'))
solver.add(inputString[2] == ord('F'))
solver.add(inputString[3] == ord('{'))
solver.add(inputString[len(flag)-1] == ord('}'))


#CTF{CWqCdrIhWexrJgutReUllI0u6}

#CTF{CWqCSpIsWYirVButReallyFuE}
"""
# slowely guessing the flag till it's right and fullfills constrains!

solver.add(inputString[4] == ord('C'))
solver.add(inputString[5] == ord('p'))
solver.add(inputString[6] == ord('p'))
solver.add(inputString[7] == ord('C'))
solver.add(inputString[8] == ord('l'))
solver.add(inputString[9] == ord('r'))
solver.add(inputString[8] == ord('I'))
solver.add(inputString[9] == ord('t'))
solver.add(inputString[10] == ord('I'))
solver.add(inputString[11] == ord('s'))
solver.add(inputString[12] == ord('W'))
solver.add(inputString[13] == ord('e'))
solver.add(inputString[14] == ord('i'))
solver.add(inputString[15] == ord('r'))
solver.add(inputString[16] == ord('d'))
solver.add(inputString[17] == ord('B'))
solver.add(inputString[18] == ord('u'))
solver.add(inputString[19] == ord('t'))
solver.add(inputString[20] == ord('R'))
solver.add(inputString[21] == ord('e'))
solver.add(inputString[22] == ord('a'))
solver.add(inputString[23] == ord('l'))
solver.add(inputString[24] == ord('l'))
solver.add(inputString[25] == ord('y'))

solver.add(inputString[26] == ord('F'))
solver.add(inputString[27] == ord('u'))
solver.add(inputString[28] == ord('n'))
"""

SMORBOLLv = BitVec("v", BITNESS)
solver.add(SMORBOLL(outputString) == SMORBOLLv)
solver.add(SMORBOLL(outputString)&63 == outputString[len(flag)-2]&0xFF)

solver.add(Distinct(outputString))
solver.add(outputString[1] == 25)
solver.add(outputString[2] == 23)
solver.add(outputString[9] == 9)
solver.add(outputString[20] == 45)
solver.add(outputString[26] == 7)
solver.add(outputString[12] <= 4)
solver.add(outputString[14] >= 48)
solver.add(outputString[29] >= 1)

solver.add(outputString[0] + outputString[1] + outputString[2] + outputString[3] + outputString[4] - 130 <= 10)
solver.add(outputString[5] + outputString[6] + outputString[7] + outputString[8] + outputString[9] - 140 <= 10)
solver.add(outputString[10] + outputString[11] + outputString[12] + outputString[13] + outputString[14] - 150 <= 10)
solver.add(outputString[15] + outputString[16] + outputString[17] + outputString[18] + outputString[19] - 160 <= 10)
solver.add(outputString[20] + outputString[21] + outputString[22] + outputString[23] + outputString[24] - 170 <= 10)

solver.add(outputString[0] + outputString[5] + outputString[10] + outputString[15] + outputString[20] + outputString[25] - 172 <= 6)
solver.add(outputString[1] + outputString[6] + outputString[11] + outputString[16] + outputString[21] + outputString[26] - 162 <= 6)
solver.add(outputString[2] + outputString[7] + outputString[12] + outputString[17] + outputString[22] + outputString[27] - 152 <= 6)
solver.add(outputString[3] + outputString[8] + outputString[13] + outputString[18] + outputString[23]  - 142 <= 6)
solver.add(outputString[4] + outputString[9] + outputString[14] + outputString[19] + outputString[24] + outputString[29] - 132 <= 6)

solver.add((outputString[27]*3 + outputString[7])*3 - outputString[5]*13 - 57 <= 28)

solver.add(outputString[22] * 3 + (outputString[14] << 2) - (outputString[20]*5) - 12 <= 70)

solver.add(((outputString[16]*2)+outputString[14])*2 + ((outputString[15] - (outputString[18]*2)) * 3) - outputString[17]*5 + outputString[13] == 0)

solver.add(outputString[6] * 2 == outputString[5])

solver.add(outputString[29] + outputString[7] == 59)

solver.add(outputString[0] == outputString[17]*6)

solver.add(outputString[8] == outputString[9]*4)

solver.add(outputString[11] << 1 == outputString[13]*3)

solver.add(outputString[13] + outputString[29] + outputString[11] + outputString[4] == outputString[19])

solver.add(outputString[12]*13 == outputString[10])

while (solver.check()):
    model = solver.model()

    inputStr = ""
    outputStr = ""
    for i in range(len(outputString)):
        inputStr = inputStr + chr(model[inputString[i]].as_long())
        outputStr = outputStr + hex(model[outputString[i]].as_long())+" "

    print(inputStr)

    solver.add(Or([inputString[i] != model[inputString[i]] for i in range(len(flag))]))

