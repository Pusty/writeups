from capstone import *
import copy

import sys
sys.setrecursionlimit(50000)

# The challenge binary
f = open("dist-22621.exe", "rb")
FILE_DATA = f.read()
f.close()

# Hardcoded offsets from the binary  (adjust for different builds)
CODE = FILE_DATA[:0x495a26][0x1000:] # base address 0x401000
DATA = FILE_DATA[0x496000:]          # base address 0xA00000

TABLE = {}
# https://github.com/hfiref0x/SyscallTables/blob/master/Compiled/Composition/X86_64/NT10/ntos/
# ntos syscall number to name mapping for the binary
f = open("nt_22631.txt", "r")
lines = f.read().split("\n")
f.close()


for line in lines[:-1]:
    name, nr = line.split("\t")
    TABLE[int(nr)] = name

baseRegs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


md = Cs(CS_ARCH_X86, CS_MODE_64)

def makeRegs64(inp):
    if inp.startswith("e"):
        inp = "r"+inp[1:]
    if inp.endswith("w"):
        inp = inp[:-1]
    if inp.endswith("d"):
        inp = inp[:-1]
    if len(inp) == 2 and inp[1] not in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]:
        inp = "r"+inp
    return inp


# this is way faster, as slicing a huge array was bottle neck before
assembly = []
assemblyIndex = {}
assemblyCounter = 0
for asmObj in md.disasm(CODE, 0x401000):
    assembly.append(asmObj)
    assemblyIndex[asmObj.address] = assemblyCounter
    assemblyCounter = assemblyCounter + 1


def process(state):
    ii = assemblyIndex[0x401000+state["start"]]
    while True:
        i = assembly[ii]
        ii += 1
        if i.mnemonic == "mov":
            reg, val = i.op_str.split(", ")
            reg = makeRegs64(reg)
            val = makeRegs64(val)
            #if val in state["regs"]:
            #    state["regs"][reg] = state["regs"][val]
            #else:
            state["regs"][reg] = val
        elif i.mnemonic == "movabs":
            reg, val = i.op_str.split(", ")
            reg = makeRegs64(reg)
            state["regs"][reg] = val
        elif i.mnemonic == "syscall":
            state["func"] = TABLE[int(state["regs"]["rax"], 16)&0xfff]
            state["endOfBlock"] = True if state["func"] == "NtContinue" else False
            state["end"] = (i.address + 2)-0x401000
            
            values = []
            if "r10" in state["regs"]:
                values.append(makeRegs64(state["regs"]["r10"]))
            if "rdx" in state["regs"]:
                values.append(makeRegs64(state["regs"]["rdx"]))
            if "r8" in state["regs"]:
                values.append(makeRegs64(state["regs"]["r8"]))
            if "r9" in state["regs"]:
                values.append(makeRegs64(state["regs"]["r9"]))
            if "rsp" in state["regs"]:
                offset = int(state["regs"]["rsp"], 16) - 0xA00000
                for j in range(5, 16): # 1 filler, 4 shadow space
                    values.append(hex(int.from_bytes(DATA[offset+j*8:offset+(j+1)*8], byteorder='little')))
            
            state["args"] = values
            
            break
    return state

def getJumpAddress(state):
    buffer = int(state["args"][0], 16) - 0xA00000
    addr = int.from_bytes(DATA[buffer+0xF8:buffer+0xF8+8], byteorder='little')
    return addr
    
def evalAddTo(state, overwrite=None):
    key = "dword ptr ["+state["args"][2]+"]"
    if key in state["regs"]:
        addValue = state["regs"][key]
    else:
        addValue = key
    return "addTo("+(state["args"][0] if overwrite == None else overwrite)+", "+makeRegs64(addValue)+");"

def evalReadVal(stateBefore, stateAfter, overwrite=None):
    key = hex(int(stateBefore["args"][2], 16)+ 0x20)
    for rN in stateAfter["regs"]:
        if key in stateAfter["regs"][rN]:
            return(makeRegs64(rN)+" = readFrom("+(stateBefore["args"][0] if overwrite == None else overwrite)+");")

def evalIOCreate(state):
    return "qword ["+state["args"][0]+"] = NtCreateIoCompletion()"

def evalFactoryCreate(stateBefore, stateAfter):
    key = stateBefore["args"][0]
    options = []
    for rN in stateAfter["regs"]:
        if key in stateAfter["regs"][rN] and (not rN in stateBefore["regs"] or not key in stateBefore["regs"][rN]):
            rN = makeRegs64(rN)
            if rN in ["r10", "r8", "r9", "rdx"]:
                continue
            options.append(rN)
    
    if len(options) > 1:
        return ("// More than one option for factory "+str(options))
    else:
        return options[0]+" = createZeroFactory();"


factoryHits = 0
factoryMax = 0xffffff

def insertMov(state, depth):
    for rN in state["regs"]:
        if rN in ["r11", "r12", "r13", "r14", "r15", "rbp", "rsi", "rdi"] and state["regs"][rN] in ["r11", "r12", "r13", "r14", "r15", "rbp", "rsi", "rdi"]:
            print(depth+""+rN+" = "+state["regs"][rN]+";")
        
        
def processBlock(addr, depth, already):
    global factoryHits
    
    funcs = []
    states = []

    lastState = {}
    lastState["start"] =  addr - 0x401000
    
    if(lastState["start"] in already):
        print(depth+"goto LABEL_"+hex(lastState["start"]+0x401000)+";")
        return
    
    already.append(lastState["start"])
    lastState["regs"] = {}
    lastState["endOfBlock"] = False
    lastState["end"] = lastState["start"]
    lastState["func"] = ""
    
    while not lastState["endOfBlock"]:
        state = copy.deepcopy(lastState)
        
        state["func"] = ""
        state["regs"]["rax"] = "retval"
        
        state["start"] = lastState["end"]
        process(state)
        
        if len(states) > 0 and states[-1]["func"] == "NtCreateIoCompletion":
            state["regs"] = {}
        
        funcs.append(state["func"])
        states.append(state)
        lastState = state

    print(depth+"LABEL_"+hex(states[0]["start"]+0x401000)+":")
    
    
    if len(funcs) == 3 and funcs[0] == "NtCreateSemaphore" and funcs[1] == "NtContinueEx" and funcs[2] == "NtContinue":
        insertMov(states[0], depth)
        print(depth+"if("+states[0]["args"][3]+" <= "+states[0]["args"][4]+") {")
        insertMov(states[1], depth)
        addrTrue = getJumpAddress(states[1])
        processBlock(addrTrue, depth+"  ", already)
        print(depth+"} else {")
        insertMov(states[2], depth)
        addrFalse = getJumpAddress(states[2])
        processBlock(addrFalse, depth+"  ", already)
        print(depth+"}")
    # block for checking if inp is equal to 0
    elif len(funcs) == 2 and funcs[0] == "NtContinueEx" and funcs[1] == "NtContinue":
        insertMov(states[0], depth)
        print(depth+"if("+states[0]["regs"]['qword ptr [rdx + 0x10]']+" == 0) {")
        addrTrue = getJumpAddress(states[0])
        processBlock(addrTrue, depth+"  ", already)
        print(depth+"} else {")
        addrFalse = getJumpAddress(states[1])
        insertMov(states[1], depth)
        processBlock(addrFalse, depth+"  ", already)
        print(depth+"}")
    # add to both values, then read one new
    elif len(funcs) == 4 and funcs[0] == "NtSetInformationWorkerFactory" and funcs[1] == "NtSetInformationWorkerFactory" and funcs[2] == "NtQueryInformationWorkerFactory" and funcs[3] == "NtContinue":
        insertMov(states[0], depth)
        print(depth+evalAddTo(states[0]))
        insertMov(states[1], depth)
        print(depth+evalAddTo(states[1]))
        insertMov(states[2], depth)
        print(depth+evalReadVal(states[2], states[3]))
        insertMov(states[3], depth)
        processBlock(getJumpAddress(states[3]), depth, already)
    # add, set reg, compare again
    elif len(funcs) == 5 and funcs[0] == "NtSetInformationWorkerFactory" and funcs[1] == "NtQueryInformationWorkerFactory" and funcs[2] == "NtCreateSemaphore" and funcs[3] == "NtContinueEx" and funcs[4] == "NtContinue":
        insertMov(states[0], depth)
        print(depth+evalAddTo(states[0]))
        insertMov(states[1], depth)
        print(depth+evalReadVal(states[1], states[2]))
        insertMov(states[2], depth)
        print(depth+"if("+states[2]["args"][3]+" <= "+states[2]["args"][4]+") {")
        insertMov(states[3], depth)
        addrTrue = getJumpAddress(states[3])
        processBlock(addrTrue, depth+"  ", already)
        print(depth+"} else {")
        insertMov(states[4], depth)
        addrFalse = getJumpAddress(states[4])
        processBlock(addrFalse, depth+"  ", already)
        print(depth+"}")
    elif len(funcs) == 2 and funcs[0] == "NtSetInformationWorkerFactory" and funcs[1] == "NtContinue":
        insertMov(states[0], depth)
        print(depth+evalAddTo(states[0]))
        insertMov(states[1], depth)
        processBlock(getJumpAddress(states[1]), depth, already)
    elif len(funcs) == 3 and funcs[0] == "NtSetInformationWorkerFactory" and funcs[1] == "NtQueryInformationWorkerFactory" and funcs[2] == "NtContinue":
        insertMov(states[0], depth)
        print(depth+evalAddTo(states[0]))
        insertMov(states[1], depth)
        print(depth+evalReadVal(states[1], states[2]))
        insertMov(states[2], depth)
        processBlock(getJumpAddress(states[2]), depth, already)
    elif len(funcs) == 4 and funcs[0] == "NtSetInformationWorkerFactory" and funcs[1] == "NtQueryInformationWorkerFactory" and funcs[2] == "NtContinueEx" and funcs[3] == "NtContinue":
        insertMov(states[0], depth)
        print(depth+evalAddTo(states[0]))
        insertMov(states[1], depth)
        print(depth+evalReadVal(states[1], states[2]))
        insertMov(states[2], depth)
        print(depth+"if("+states[2]["regs"]['qword ptr [rdx + 0x10]']+" == 0) {")
        addrTrue = getJumpAddress(states[2])
        processBlock(addrTrue, depth+"  ", already)
        print(depth+"} else {")
        insertMov(states[3], depth)
        addrFalse = getJumpAddress(states[3])
        processBlock(addrFalse, depth+"  ", already)
        print(depth+"}")
    elif len(funcs) == 4 and funcs[0] == "NtSetInformationWorkerFactory" and funcs[1] == "NtQueryInformationWorkerFactory" and funcs[2] == "NtSetInformationWorkerFactory" and funcs[3] == "NtContinue":
        insertMov(states[0], depth)
        print(depth+evalAddTo(states[0]))
        insertMov(states[1], depth)
        print(depth+evalReadVal(states[1], states[2]))
        insertMov(states[2], depth)
        print(depth+evalAddTo(states[2]))
        processBlock(getJumpAddress(states[3]), depth, already)
    elif factoryHits <= factoryMax and len(funcs) == 6 and funcs[0] == "NtQueryInformationWorkerFactory" and funcs[1] == "NtCreateIoCompletion" and funcs[2] == "NtCreateWorkerFactory" and funcs[3] == "NtCreateWorkerFactory" and funcs[4] == "NtContinueEx" and funcs[5] == "NtContinue":
        factoryHits = factoryHits + 1
        insertMov(states[0], depth)
        print(depth+evalReadVal(states[0], states[1]))
        insertMov(states[1], depth)
        #print(depth+evalIOCreate(states[1]))
        insertMov(states[2], depth)
        print(depth+evalFactoryCreate(states[2], states[3]))
        insertMov(states[3], depth)
        print(depth+evalFactoryCreate(states[3], states[4]))
        insertMov(states[4], depth)
        insertMov(states[5], depth)
        addr = getJumpAddress(states[5])
        processBlock(addr, depth, already)
        
    elif factoryHits <= factoryMax and  len(funcs) == 7 and funcs[0] == "NtQueryInformationWorkerFactory" and funcs[1] == "NtCreateIoCompletion" and funcs[2] == "NtCreateWorkerFactory" and funcs[3] == "NtCreateWorkerFactory" and funcs[4] == "NtCreateWorkerFactory" and funcs[5] == "NtContinueEx" and funcs[6] == "NtContinue":
        factoryHits = factoryHits + 1
        insertMov(states[0], depth)
        print(depth+evalReadVal(states[0], states[1]))
        insertMov(states[1], depth)
        #print(depth+evalIOCreate(states[1]))
        insertMov(states[2], depth)
        print(depth+evalFactoryCreate(states[2], states[3]))
        insertMov(states[3], depth)
        print(depth+evalFactoryCreate(states[3], states[4]))
        insertMov(states[4], depth)
        print(depth+evalFactoryCreate(states[4], states[5]))
        insertMov(states[5], depth)
        insertMov(states[6], depth)
        addr = getJumpAddress(states[6])
        processBlock(addr, depth, already)
    elif factoryHits <= factoryMax and len(funcs) == 5 and funcs[0] == "NtCreateIoCompletion" and funcs[1] == "NtCreateWorkerFactory" and funcs[2] == "NtCreateWorkerFactory" and funcs[3] == "NtContinueEx" and funcs[4] == "NtContinue":
        # seems to work
        factoryHits = factoryHits + 1
        insertMov(states[0], depth)
        #print(depth+evalIOCreate(states[0]))
        insertMov(states[1], depth)
        print(depth+evalFactoryCreate(states[1], states[2]))
        insertMov(states[2], depth)
        print(depth+evalFactoryCreate(states[2], states[3]))
        insertMov(states[3], depth)
        insertMov(states[4], depth)
        addr = getJumpAddress(states[4])
        processBlock(addr, depth, already)
    elif factoryHits <= factoryMax and len(funcs) == 6 and funcs[0] == "NtCreateIoCompletion" and funcs[1] == "NtCreateWorkerFactory" and funcs[2] == "NtSetInformationWorkerFactory" and funcs[3] == "NtSetInformationWorkerFactory" and funcs[4] == "NtQueryInformationWorkerFactory" and funcs[5] == "NtContinue":
        # seems to work (a+b)
        factoryHits = factoryHits + 1
        insertMov(states[0], depth)
        #print(depth+evalIOCreate(states[0]))
        insertMov(states[1], depth)
        stringy = evalFactoryCreate(states[1], states[2])
        actualKey = stringy.split(" = ")[0].strip()
        print(depth+stringy)
        insertMov(states[2], depth)
        print(depth+evalAddTo(states[2], actualKey))
        insertMov(states[3], depth)
        print(depth+evalAddTo(states[3], actualKey))
        insertMov(states[4], depth)
        print(depth+evalReadVal(states[4], states[5], actualKey))
        insertMov(states[5], depth)
        addr = getJumpAddress(states[5])
        processBlock(addr, depth, already)
    elif len(funcs) == 3 and funcs[0] == "NtQueryInformationWorkerFactory" and funcs[1] == "NtContinueEx" and funcs[2] == "NtContinue":
        insertMov(states[0], depth)
        print(depth+evalReadVal(states[0], states[1]))
        insertMov(states[1], depth)
        print(depth+"if("+states[1]["regs"]['qword ptr [rdx + 0x10]']+" == 0) {")
        addrTrue = getJumpAddress(states[1])
        processBlock(addrTrue, depth+"  ", already)
        print(depth+"} else {")
        insertMov(states[2], depth)
        addrFalse = getJumpAddress(states[2])
        processBlock(addrFalse, depth+"  ", already)
        print(depth+"}")
    elif len(funcs) == 2 and funcs[0] == "NtQueryInformationWorkerFactory" and funcs[1] == "NtContinue":
        insertMov(states[0], depth)
        print(depth+evalReadVal(states[0], states[1]))
        insertMov(states[1], depth)
        addr = getJumpAddress(states[1])
        processBlock(addr, depth, already)
    #elif len(funcs) == 3 and funcs[0] == "NtReadVirtualMemory" and funcs[0] == "NtWriteVirtualMemory" and funcs[1] == "NtContinue":
    #    if(states[0]["args"][3] == "1"):
    #        # 1
    #        print(depth+"byte ["+states[0]["args"][2]+"] = byte ["+states[0]["args"][1]+"]")
    #        print(depth+"byte ["+states[1]["args"][1]+"] = byte ["+states[1]["args"][2]+"]")
    #    else:
    #        # 4
    #        print(depth+"dword ["+states[0]["args"][2]+"] = dword ["+states[0]["args"][1]+"]")
    #        print(depth+"dword ["+states[1]["args"][1]+"] = dword ["+states[1]["args"][2]+"]")
    #    addr = getJumpAddress(states[2])
    #    processBlock(addr, depth, already)
    elif len(funcs) == 1 and funcs[0] == "NtContinue":
        insertMov(states[0], depth)
        addr = getJumpAddress(states[0])
        processBlock(addr, depth, already)
    else:
        print("// "+hex(states[0]["end"]-2+0x401000), funcs)


# block 5
#processBlock(0x5C726E, "", [])

# block 4
#processBlock(0x443F66, "", [])

# block 3
#processBlock(0x88E271, "", [])

# block2:
#processBlock(0x70FAE5, "", [])

# block1:
#processBlock(0x725A0C, "", [])

# block0:
processBlock(0x4014FF, "", [])
