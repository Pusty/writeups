from capstone import *


loopFunc = 0x400080
loopFuncLen = 0x4000e1-loopFunc

bigdataArray = 0x400176
bigdataArrayLen = 0x4c7556-bigdataArray

MAGIC_VALUE = 0x49da


md = Cs(CS_ARCH_X86, CS_MODE_64)
binaryFile = open("main.elf", "rb")
data = binaryFile.read()

loopFuncMem = data[0x80:0x80+loopFuncLen]
bigArrayMem = data[0x176:0x176+bigdataArrayLen]

loopFuncMem = [b for b in loopFuncMem]
bigArrayMem = [b for b in bigArrayMem]

binaryFile.close()




shortestPath = {}

def registerPath(path, add):
    revAdd = 0
    if path[-1] in shortestPath:
        revAdd = shortestPath[path[-1]]
    else:
        revAdd = add[-1]

    for r in range(1, len(path)+1):
        if r > 1: revAdd = revAdd + add[-r]
        if path[-r] in shortestPath:
            shortestPath[path[-r]] = min(shortestPath[path[-r]], revAdd)
        else:
            shortestPath[path[-r]] = revAdd

def parseBranch(mem, rbx, val, depth=0, path=[], add=[]):

   
    if rbx in shortestPath:
        registerPath(path, add)
        if shortestPath[rbx]+val > MAGIC_VALUE:
            return
            
        # this prevents unnecessary calculations
        if shortestPath[rbx]+val > 14000 and depth < 400:
            return
            
        if shortestPath[rbx]+val > 12000 and depth < 200:
            return
    
    
    if depth == 100*8: 
        registerPath(path, add)
        return

    # apply self modifying xor
    for i in range(8*4):
        mem[i] ^= bigArrayMem[rbx+i]

    currentAdd = 0
    nextPointer = 0
    existingJumps = []
    
    for i in md.disasm(bytes(mem), 0x2d):
        op = i.mnemonic
        if op == "nop": 
            continue
        if op == "je":
            continue
        if op == "jmp":
            existingJumps.append((nextPointer, currentAdd))
            continue
        if op == "add":
            currentAdd = int(i.op_str.split(",")[1].strip(), 16)
            continue
        if op == "lea":
            nextPointer = int(i.op_str.split("+")[1].split("]")[0].strip(), 16)
            continue
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)) # print if unexpected stuff occurs
    
    for (nextPointer, currentAdd)  in existingJumps:
        parseBranch(mem+[], nextPointer, val+currentAdd, depth+1, path+[nextPointer], add+[currentAdd])
    
    
# calculate shortest paths
parseBranch(loopFuncMem[0x2d:], 0, 0)


def verboseCalc(mem, rbx, val, depth=0, bits=[]):

    if depth == 100*8: 
        barray = ''.join('0' if b == 0 else '1' for b in bits)
        # print flag
        print(''.join([chr(int(barray[i*8:(i+1)*8][::-1],2)) for i in range(len(barray)//8)]))
        return
        
    # apply self modifying xor
    for i in range(8*4):
        mem[i] ^= bigArrayMem[rbx+i]

    currentAdd = 0
    nextPointer = 0
    
    
    existingJumps = []
    
    for i in md.disasm(bytes(mem), 0x2d):
        op = i.mnemonic
        if op == "jmp":
            existingJumps.append((nextPointer, currentAdd))
        if op == "add":
            currentAdd = int(i.op_str.split(",")[1].strip(), 16)
        if op == "lea":
            nextPointer = int(i.op_str.split("+")[1].split("]")[0].strip(), 16)
    
    jo = shortestPath[existingJumps[0][0]]
    jz = shortestPath[existingJumps[1][0]]

    if jo+val == MAGIC_VALUE:
        verboseCalc(mem+[], existingJumps[0][0], val+existingJumps[0][1], depth+1, bits+[1])
    if jz+val == MAGIC_VALUE:
        verboseCalc(mem+[], existingJumps[1][0], val+existingJumps[1][1], depth+1, bits+[0])

# use shortest paths map and traverse it
verboseCalc(loopFuncMem[0x2d:], 0, 0)