v = [98, 57, 35, 34, 42, 41, 104, 79, 18, 28, 29, 75, 55, 0, 49, 33, 37, 46, 65, 21, 120, 99, 123, 68, 112, 20, 78, 19, 61, 31, 54, 122, 39, 123, 23, 29, 30, 52, 7, 5, 103, 7, 95, 127, 5, 57, 58, 6, 105, 84, 60, 55, 34, 44, 100, 90, 84, 100, 4, 12, 59, 54, 64, 76, 92, 120]
compareBuf = [v[i] ^ i for i in range(len(v))]

def sign_i32(value):
    value = value & ((1<<32)-1)
    value = (value ^ (1<<31)) - (1<<31)
    return value

def computeval(a,b):
    for i in range(16):
        a = sign_i32(a)
        a = (a >> 15)^a
        a = sign_i32(a)
        a = ((a << 13)^a)
        a = sign_i32(a)
        a = (a >> 17)^a
        a = sign_i32(a)
        b = b ^ a
        a = (b >> 11)^a
        a = sign_i32(a)
    return a ^ b
    
def encode(flag):
    xorVal = 3554697097
    out = []
    for i in range(len(flag)):
        c = ord(flag[i])
        out.append(c^(xorVal & 95))
        xorVal = computeval(xorVal, c)
    return bytes(out)
    
def decode(buffer):
    xorVal = 3554697097
    inp = []
    for i in range(len(buffer)):
        for c in range(0x20, 0x7f):
            if c^(xorVal & 95) == buffer[i]:
                inp.append(c)
                xorVal = computeval(xorVal, c)
                break
                
    return bytes(inp)

print(compareBuf)
flag = "Hello World"
print(decode(encode(flag)))


print(decode(compareBuf))
