# copied from L5200
compareArray = [0x14, 0x1e, 0xc, 0xe0, 0x30, 0x5c, 0xce, 0xf0, 0x36, 0xae, 0xfc, 0x39, 0x1a, 0x91, 0xce, 0xb4, 0xc4, 0xe, 0x18, 0xf3, 0xc8, 0x8e, 0xa, 0x85, 0xf6, 0xbd]
# copied from L521A
xorArray = [0x43, 0x11, 0x37, 0xf2, 0x69, 0xab, 0x2c, 0x99, 0x13, 0x12, 0xd1, 0x7e, 0x9a, 0x8f, 0xe, 0x92, 0x37, 0xf4, 0xaa, 0x4d, 0x77, 0x3, 0x89, 0xca, 0xff, 0x1a]

# https://gist.github.com/vqhuy/a7a5cde5ce1b679d3c0a

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
 
# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def encode(inpStr):
    values = []
    for i in range(len(inpStr)): # the program actually fixes this at 0x1A bytes
        if (i & 1) == 1:
            values.append(rol(ord(inpStr[i])^xorArray[i-1], 1, 8))
        else:
            values.append(rol(ord(inpStr[i])^ord(inpStr[i+1]), 1, 8))
    
    return values
    
    
def decode(encodedArr):
    decodedStr = []
    
    oddDecode = lambda i: ror(encodedArr[i], 1, 8) ^ xorArray[i-1]
    evenDecode = lambda i: ror(encodedArr[i], 1, 8) ^ oddDecode(i+1)
    
    for i in range(len(encodedArr)):
        if (i & 1) == 1:
            decodedStr.append(chr(oddDecode(i)))
        else:
            decodedStr.append(chr(evenDecode(i)))
            
    return ''.join(decodedStr)
    
    
def checkflag(encodedArr):
    if len(encodedArr) != len(compareArray): return False 
    for i in range(len(compareArray)): # the program actually fixes this at 0x1A bytes
        if compareArray[i] != encodedArr[i]:
            return False
    return True
    
    
print("Decode(Encode(test)): ", decode(encode("test")))
print("Decode(compareArray): ", decode(compareArray))
print("Check(Encode(flag)):  ",checkflag(encode("FLAG_G3T_D3M_R3TR0_ST0NKZ!")))