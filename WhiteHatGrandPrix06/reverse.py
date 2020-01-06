f = open("output.png", "rb")

arrayOfArrays = []
amountRead    = 0
for i in range(15):
    arrayOfArrays.append([ord(c) for c in f.read(0x1000)])
    amountRead = len(arrayOfArrays[i])
f.close()
    
changeData = [0,0x1B,0xBA,0x30,0x50,0xB1,0x7E,0xD4,0x0F,0x44,0x31,0x77,0xD6,0xB5]

randomArray = [0]*0xF000
for n in range(amountRead+0xE000):
    randomArray[n] = arrayOfArrays[n/0x1000][n&0xFFF]
    

def SHF(data, length):
    hash = 0x2FD2B4
    for i in range(length):
        hash = data[i] ^ hash
        hash = hash * 0x66EC73
    return hash&0xFFFFFFFFFFFFFFFF
        
arr = [  7,
        54,
        61,
        61,
        59,
        56,
        58,
        80,
        83,
        79,
        85,
        83,
        38,
        12]


for ii in range(14):
    randomArray[0x1000*ii+10] = arr[ii]
    arrayOfArrays[ii][10] = arr[ii]

# Swap back to original data
for k in range(7):
    if (arrayOfArrays[2*k][0] + arrayOfArrays[2*k+1][0])&1 == 0:
        tmp = arrayOfArrays[2*k]+[]
        arrayOfArrays[2*k] = arrayOfArrays[2*k+1]+[]
        arrayOfArrays[2*k+1] = tmp
        

hashValue = SHF(randomArray, amountRead + 0xE000);
c1 = chr((hashValue-0x7D)&0xFF)
c2 = chr(((hashValue>>8)+0x7C)&0xFF)
print(str(hashValue)+" -> "+chr((hashValue-0x7D)&0xFF)+" "+chr(((hashValue>>8)+0x7C)&0xFF))
print(hex((((hashValue >> 24)&0xFFFF)-0x5100)&0xFFFF))

outputData = [0]*(amountRead+0xE000)
for n in range(amountRead+0xE000):
    outputData[n] = arrayOfArrays[n/0x1000][n&0xFFF]

f = open("data", "wb")
f.write(''.join([chr(c) for c in outputData]))
f.close()


"""    
possible for [1,2,3]
54, 61, 61
61, 54, 61
61, 61, 54
"""

"""
possible for [4,5,6,7]
56, 58, 59, 80
56, 59, 58, 80
57, 61, 61, 78
58, 56, 59, 80
58, 59, 56, 80
58, 59, 60, 84
58, 60, 59, 84
59, 56, 58, 80
59, 58, 56, 80
59, 58, 60, 84
59, 59, 61, 84
59, 60, 58, 84
59, 61, 59, 84
60, 58, 59, 84
60, 59, 58, 84
61, 57, 61, 78
61, 59, 59, 84
61, 61, 57, 78
"""

"""
possible for 8
range(77, 77+10)
"""

"""
possible for [9,10,11,12]
77, 79, 80, 35
77, 80, 79, 35
77, 81, 81, 34
77, 81, 84, 41
77, 84, 81, 41
78, 78, 86, 39
78, 86, 78, 39
79, 77, 80, 35
79, 80, 77, 35
79, 82, 82, 36
79, 83, 85, 38
79, 85, 83, 38
80, 77, 79, 35
80, 79, 77, 35
80, 81, 81, 37
80, 82, 84, 39
80, 84, 82, 39
81, 77, 81, 34
81, 77, 84, 41
81, 80, 81, 37
81, 81, 77, 34
81, 81, 80, 37
81, 82, 83, 35
81, 83, 82, 35
81, 84, 77, 41
82, 79, 82, 36
82, 80, 84, 39
82, 81, 83, 35
82, 82, 79, 36
82, 83, 81, 35
82, 84, 80, 39
83, 79, 85, 38
83, 81, 82, 35
83, 82, 81, 35
83, 85, 79, 38
84, 77, 81, 41
84, 80, 82, 39
84, 81, 77, 41
84, 82, 80, 39
85, 79, 83, 38
85, 83, 79, 38
86, 78, 78, 39
"""


"""
import math


def confirm(org):
    if org[0] == 7 and org[13] == 12:
        for l in range(1, 7):
            if ((org[l] - 52)&0xFF) > 9:
                return -2
        for l in range(7, 12):
            if ((org[l] - 77)&0xFF) > 9:
                return -3
        if org[12] - 34 <= 9:
            v4 = org[1] ** 3
            v5 = (org[2] ** 3) + v4
            v28 = int(math.floor((org[3] ** 3) + v5))&0xFF
            if v28 != 0x62: return -4
            v6 = org[4]**3
            v7 = (org[5] ** 3) + v6
            v8 = (org[6] ** 3) + v7
            v28 = int(math.floor(org[7]**3)+v8)&0xFF
            if v28 != 0x6B: return -5
            v9 = org[9] ** 3
            v10 = (org[10] ** 3) + v9
            v11 = (org[11] ** 3) + v10
            v28 = int(math.floor(org[12]**3)+v11)&0xFF
            if v28 != 0xBF: return -6
            return 0
    return -1
"""