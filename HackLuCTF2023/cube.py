CUBE_LENGTH = 0x28
CUBE_LENGTH_M1 = CUBE_LENGTH-1

def convChar(c):
    rcx = (c - 0x30)&0xff
    if rcx <= 0x4d:
        if rcx >= 0 and rcx <= 9:
            return (c-0x30)&0xff
        if rcx >= 0x11 and rcx <= 0x2a:
            return (c-0x37)&0xff
        if rcx >= 0x31 and rcx <= 0x4a:
            return (c-0x3d)&0xff
        if rcx == 0x4d:
            return 0x3f
        if (((((((((((((((((((((((((((rcx == 0x11 or rcx == 0x12) or rcx == 0x13) or rcx == 0x14) or rcx == 0x15) or rcx == 0x16) or rcx == 0x17) or rcx == 0x18) or rcx == 0x19) or rcx == 0x1a) or rcx == 0x1b) or rcx == 0x1c) or rcx == 0x1d) or rcx == 0x1e) or rcx == 0x1f) or rcx == 0x20) or rcx == 0x21) or rcx == 0x22) or rcx == 0x23) or rcx == 0x24) or rcx == 0x25) or rcx == 0x26) or rcx == 0x27) or rcx == 0x28) or rcx == 0x29) or rcx == 0x2a) or rcx == 0x4b)):
            return 0x3e
    return None


def read_a(buf, i, j, x, y):
    if y == 0:
        return buf[i][j][x]
    elif y == 1:
        return buf[i][x][j]
    elif y == 2:
        return buf[x][i][j]
    
def write_a(buf, i, j, x, y, v):
    if y == 0:
        buf[i][j][x] = v
    elif y == 1:
        buf[i][x][j] = v
    elif y == 2:
        buf[x][i][j] = v
        

def rotate_cub(buf, x, y):
    for i in range(CUBE_LENGTH//2):
        for j in range(i, CUBE_LENGTH_M1-i):
            v = read_a(buf, i, j, x, y)
            write_a(buf, i,                    j,                    x, y, read_a(buf, j,                    (CUBE_LENGTH_M1 - i), x, y))
            write_a(buf, j,                    (CUBE_LENGTH_M1 - i), x, y, read_a(buf, (CUBE_LENGTH_M1 - i), (CUBE_LENGTH_M1 - j), x, y))
            write_a(buf, (CUBE_LENGTH_M1 - i), (CUBE_LENGTH_M1 - j), x, y, read_a(buf, (CUBE_LENGTH_M1 - j), i,                    x, y))
            write_a(buf, (CUBE_LENGTH_M1 - j), i,                    x, y, v)

def unrotate_cub(buf, x, y):
    for i in range((CUBE_LENGTH//2)-1, -1, -1):
        for j in range((CUBE_LENGTH_M1-i)-1, i-1, -1):
            v = read_a(buf, (CUBE_LENGTH_M1 - j), i, x, y)
            write_a(buf, (CUBE_LENGTH_M1 - j), i, x, y, read_a(buf, (CUBE_LENGTH_M1 - i), (CUBE_LENGTH_M1 - j), x, y))
            write_a(buf, (CUBE_LENGTH_M1 - i), (CUBE_LENGTH_M1 - j), x, y, read_a(buf, j, (CUBE_LENGTH_M1 - i), x, y))
            write_a(buf, j, (CUBE_LENGTH_M1 - i), x, y, read_a(buf, i, j, x, y))
            write_a(buf, i, j, x, y, v)

def flatten(buf):
    return [buf[i//(CUBE_LENGTH*CUBE_LENGTH)][(i - ((i//(CUBE_LENGTH*CUBE_LENGTH))*CUBE_LENGTH*CUBE_LENGTH))//CUBE_LENGTH][(i - ((i//(CUBE_LENGTH*CUBE_LENGTH))*CUBE_LENGTH*CUBE_LENGTH))%CUBE_LENGTH] for i in range(CUBE_LENGTH**3)]

def makeCube():
    return [[[x+z*CUBE_LENGTH+y*(CUBE_LENGTH*CUBE_LENGTH) for x in range(CUBE_LENGTH)] for z in range (CUBE_LENGTH)] for y in range(CUBE_LENGTH)]
    
def copyCube(buf):
    return [[[buf[y][z][x] for x in range(CUBE_LENGTH)] for z in range (CUBE_LENGTH)] for y in range(CUBE_LENGTH)]
    
def printCube(buf):
    print("=========")
    for y in range(CUBE_LENGTH):
        print(buf[y])  
        
def hashCube(s):
    hashVal = [convChar(ord(s[i])) for i in range(len(s))]
    bigBuffer = makeCube()
    for x in range(len(s)):
        for y in range(3):
            k3 = (hashVal[x] >> (y*2))&3
            for k in range(k3):
                rotate_cub(bigBuffer, x, y)
    return bigBuffer


def unhashCube(targetCube, x=0, already="", ln=CUBE_LENGTH):
    if x == ln:
        return already
    convCubeT = hashCube(already)

    sols = []
    for c in range(0x30, 0x7f):
        conv = convChar(c)
        if conv == None: continue

        convCube = copyCube(convCubeT)
        for y in range(3):
            k3 = (conv >> (y*2))&3
            for k in range(k3):
                rotate_cub(convCube, x, y)

        if convCube[x][x][x] != targetCube[x][x][x]:
            continue
        
        bad = False
        for i in range(x+1):
            for j in range(x+1):
                for k in range(x+1):
                    if convCube[i][j][k] != targetCube[i][j][k]:
                        bad = True
                        break
                if bad:
                    break
            if bad:
                break
        if not bad:
            sols.append(chr(c))
    print(x, sols)
    for c in sols:
        res = unhashCube(targetCube, x+1, already+c, ln)
        if res is not None:
            return res
    return None

def makeCubeFromBinary():
    f = open("chall", "rb")
    data = f.read()[0x0002150:]
    f.close()
    import struct
    return [[[struct.unpack("<I", data[((y*0x28*0x28)+(z*0x28)+x)*4:][:4])[0] for x in range(CUBE_LENGTH)] for z in range (CUBE_LENGTH)] for y in range(CUBE_LENGTH)]

hashed = makeCubeFromBinary()
print(unhashCube(hashed))