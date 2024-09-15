def swap(arr, i, j):
    if i == j: return
    v = arr[i]
    arr[i] = arr[j]
    arr[j] = v

def srand(seed):
    global state
    state = seed

def rand():
    global state
    state = (0x5851f42d4c957f2d * state + 1) & (2**64-1)
    return state>>32

def encode_stage1(flag):
    buffer = [0 for _ in range(0x20)]
    numArray20 = [i for i in range(0x20)]
    numArray100 = [i for i in range(0x100)]

    for i in range(1337):
        for j in range(1000):
            swap(numArray20, rand() % 0x20, rand() % 0x20)
        for j in range(10000):
            swap(numArray100, rand() & 0xff, rand() & 0xff)
        for j in range(0x20):
            buffer[j] = flag[numArray20[j]]
        for j in range(0x20):
            flag[j] = buffer[numArray20[j]]
        for j in range(0x20):
            flag[j] = numArray100[flag[j]]
        for j in range(0x20):
            flag[j] = (rand()&0xff) ^ flag[j]
            
    
def decode_stage1(flag):
    swapValues20 = []
    swapValues100 = []
    xorValues = []
    
    # precompute all rand() values in the same order
    for i in range(1337):
        swapValues20a = []
        swapValues100a = []
        xorValuesa = []
        for j in range(1000):
            swapValues20a.append((rand() % 0x20, rand() % 0x20))
        for j in range(10000):
            swapValues100a.append((rand() & 0xff, rand() & 0xff))
        for j in range(0x20):
            xorValuesa.append((rand()&0xff))
        
        swapValues20.append(swapValues20a)
        swapValues100.append(swapValues100a)
        xorValues.append(xorValuesa)
    
    buffer = [0 for _ in range(0x20)]
    numArray20 = [i for i in range(0x20)]
    numArray100 = [i for i in range(0x100)]

    # swap arrays to end constellation
    for i in range(1337):
        for j in range(1000):
            swap(numArray20, swapValues20[i][j][0], swapValues20[i][j][1])
        for j in range(10000):
            swap(numArray100, swapValues100[i][j][0], swapValues100[i][j][1])

    for i in range(1337-1, -1, -1):
        for j in range(0x20):
            flag[j] = xorValues[i][j] ^ flag[j]
        for j in range(0x20):
            flag[j] = numArray100.index(flag[j])
        for j in range(0x20):
            buffer[j] = flag[numArray20.index(j)]
        for j in range(0x20):
            flag[j] = buffer[numArray20.index(j)]
        for j in range(1000-1, -1, -1):
            swap(numArray20, swapValues20[i][j][0], swapValues20[i][j][1])
        for j in range(10000-1, -1, -1):
            swap(numArray100, swapValues100[i][j][0], swapValues100[i][j][1])


def encode_stage2(flag):
    buffer = [0 for _ in range(0x10*0x10)]
    for j in range(0x20):
        for y in range(0x10):
            for k in range(0x10):
                buffer[0x10*y+k] = buffer[0x10*y+k] << 1
        buffer[flag[j]] ^= 1

    X = []
    for y in range(0x10):
        v = 0
        for j in range(0x10):
            v += buffer[0x10*y+j]
        X.append(v)

    Y = []
    for j in range(0x10):
        v = 0
        for y in range(0x10):
            v += buffer[0x10*y+j]
        Y.append(v)
        
    return (X, Y)

def decode_stage2(X, Y):
    flag = []
    for i in range(0x20):
        x = [(v>>(0x1f-i))&1 for v in X].index(1)
        y = [(v>>(0x1f-i))&1 for v in Y].index(1)  
        flag.append(x*0x10+y)
        
    return flag




# Test encrypt and decrypt test flag
flag = list(b'ptm{REDACTEDREDACTEDREDACTEDRED}')
srand(0)
encode_stage1(flag)
X, Y = encode_stage2(flag)
srand(0)
dflag = decode_stage2(X, Y)
decode_stage1(dflag)
print(bytearray(dflag))


# Try both possible seeds for flag text file

X = 49664, 268435456, 2147614752, 9437184, 524352, 0, 4194564, 536870912, 102760448, 134217866, 0, 0, 16, 0, 1074018305, 16843776
Y = 0, 80, 8192, 0, 256, 136052736, 0, 16778752, 2097152, 0, 541081604, 8388610, 33, 268601344, 1073741824, 2248216712


srand(0)
dflag = decode_stage2(X, Y)
decode_stage1(dflag)
print(bytearray(dflag))

srand(1)
dflag = decode_stage2(X, Y)
decode_stage1(dflag)
print(bytearray(dflag))
