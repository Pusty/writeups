import angr
import time
import subprocess
from z3 import *
from pwn import *
import sys


# ./python3 <script> <from> <to>
if len(sys.argv) != 3:
    print("./script <from> <to>")
    exit()
    
startCount = int(sys.argv[1])
endCount = int(sys.argv[2])

logfileName = "log_"+str(os.getpid())+".txt"

context.log_level='critical'
# don't make a window popup
context.terminal = ['tmux', 'new-session', '-d']


def printToSolution(s):
    f = open(logfileName, "a")
    f.write(s+"\n")
    f.close()
    print(s)

def processBinary(num):

    # Static Analysis first
    binaryName = f"{num:08d}"
    printToSolution("=N= "+binaryName)
    p = angr.Project('./rev_mvms/'+binaryName, main_opts={'custom_base_addr': 0x555555554000}, load_options={'auto_load_libs': False})

    cfg = p.analyses.CFGFast()

    xor_bp = []
    add_bp = []
    sub_bp = []

    address_added = []

    for func in cfg.kb.functions:
        for block in cfg.kb.functions[func].blocks:
            lastxor = None
            lastsub = None
            lastadd = None
            for inst in block.capstone.insns:
                if inst.mnemonic == "add":
                    lastadd = inst
                if inst.mnemonic == "sub":
                    lastsub = inst 
                if inst.mnemonic == "xor":
                    args = set([a.strip() for a in inst.op_str.split(",")])
                    if len(args) == 1: continue
                    if lastxor != None and (inst.address-lastxor.address) < 64 and inst.address not in address_added:
                        print("XOR ", lastxor, inst)
                        xor_bp.append((lastxor, inst))
                        address_added.append(inst.address)
                    lastxor = inst
                if inst.mnemonic == "adc":
                    if lastadd != None and (inst.address-lastadd.address) < 64 and inst.address not in address_added:
                        print("ADC", lastadd, inst)
                        add_bp.append((lastadd, inst))
                        address_added.append(inst.address)
                if inst.mnemonic == "sbb":
                    if lastsub != None and (inst.address-lastsub.address) < 64 and inst.address not in address_added:
                        print("SBB", lastsub, inst)
                        sub_bp.append((lastsub, inst))
                        address_added.append(inst.address)
           


    # Start dynamic analysis
   
    io = gdb.debug('./rev_mvms/'+binaryName, api=True)
    inputTemplate = 0x42424242424242424141414141414141
    chain = []
    io.sendline(b"A"*0x8+b"B"*8)

    # setup breakpoints

    def eval_args(io, args):
        if not "[" in args[0]:
            s = "$"+args[0]
            
        else:
            s = "*((uint64_t*)("+args[0].split("[")[1].split("]")[0].replace("r", "$r")+"))"
            
        a0 = int(io.gdb.execute("p/x "+s, to_string=True).split(" = ")[1], 16)
        
        if "[" not in args[1]:
            s = "$"+args[1]
            
        else:
            s = "*((uint64_t*)("+args[1].split("[")[1].split("]")[0].replace("r", "$r")+"))"

        a1 = int(io.gdb.execute("p/x "+s, to_string=True).split(" = ")[1], 16)
            
        return a0, a1
        
        
    io.gdb.execute("set pagination off")
    io.gdb.execute("set disassembly-flavor intel")
    # echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
    for bp in xor_bp+add_bp+sub_bp:
        firstpart = bp[0]
        secondpart = bp[1]
        io.gdb.execute("break *"+hex(bp[0].address))
        io.gdb.execute("break *"+hex(bp[1].address ))
        
    io.gdb.execute("catch syscall 60")
    io.gdb.execute("catch syscall 231")

    io.gdb.continue_and_wait()

    anw = io.recvline()
    fv = (0, 0)



    while True:
        # will reach breakpoints here
        pc = int(str(io.gdb.parse_and_eval ("$pc")).split(" ")[0], 16)
        found = False
        for bp in xor_bp:
            firstpart = bp[0]
            secondpart = bp[1]
            if pc == firstpart.address:
                found = True
                #print("XOR FIRST PART")
                args = [a.strip() for a in firstpart.op_str.split(",")]
                fv = eval_args(io, args)
            if pc == secondpart.address:
                found = True
                #print("XOR SECOND PART")
                args = [a.strip() for a in secondpart.op_str.split(",")]
                lv = eval_args(io, args)
                

              
                valueLeft = (lv[0] << 64) | fv[0]
                valueRight = (lv[1] << 64) | fv[1]
                
                if("8" in firstpart.op_str):
                    valueLeft = (fv[0] << 64) | lv[0]
                    valueRight = (fv[1] << 64) | lv[1]
                elif("8" in secondpart.op_str):
                    pass
                
                chain.append(("XOR", valueLeft, valueRight))
                
        for bp in add_bp:
            firstpart = bp[0]
            secondpart = bp[1]
            if pc == firstpart.address:
                found = True
                #print("ADD FIRST PART")
                args = [a.strip() for a in firstpart.op_str.split(",")]
                fv = eval_args(io, args)
            if pc == secondpart.address:
                found = True
                #print("ADD SECOND PART")
                args = [a.strip() for a in secondpart.op_str.split(",")]
                lv = eval_args(io, args)
                
                valueLeft = (lv[0] << 64) | fv[0]
                valueRight = (lv[1] << 64) | fv[1]
                
                chain.append(("ADD", valueLeft, valueRight))

                
        for bp in sub_bp:
            firstpart = bp[0]
            secondpart = bp[1]
            if pc == firstpart.address:
                found = True
                #print("SUB FIRST PART")
                args = [a.strip() for a in firstpart.op_str.split(",")]
                fv = eval_args(io, args)
            if pc == secondpart.address:
                found = True
                #print("SUB SECOND PART")
                args = [a.strip() for a in secondpart.op_str.split(",")]
                lv = eval_args(io, args)
                
                valueLeft = (lv[0] << 64) | fv[0]
                valueRight = (lv[1] << 64) | fv[1]
                
                chain.append(("SUB", valueLeft, valueRight))
                
        if found:
            io.gdb.continue_and_wait()
        else:
            io.gdb.continue_nowait()
            break
            
    anw = io.recvline()
    io.close()
    io.gdb.quit()
    
    # Done with dynamic analysis


    printToSolution("=C="+str(chain))


    x = BitVec("x", 8*16)

    inputTemplate = 0x42424242424242424141414141414141

    constantMap = {}
    reverseMap = {}
    constantMap[inputTemplate] = x
    const_index = 0

    for entry in chain:
        op = entry[0]
        left = entry[1]
        right = entry[2]
        
        
        
        if left not in constantMap:
            v = BitVec("const_"+str(const_index), 8*16)
            constantMap[left] = v
            reverseMap[v] = left
            const_index += 1
            
        if right not in constantMap:
            v = BitVec("const_"+str(const_index), 8*16)
            constantMap[right] = v
            reverseMap[v] = right
            const_index += 1
            
        if op == "XOR":
            constantMap[left^right] = constantMap[left] ^ constantMap[right]
        elif op == "ADD":
            constantMap[(left+right)&0xffffffffffffffffffffffffffffffff] = constantMap[left] + constantMap[right]
        elif op == "SUB":
            constantMap[(left-right)&0xffffffffffffffffffffffffffffffff] = constantMap[left] - constantMap[right]
        
    def countSize(expr):
        v = 1
        for c in expr.children():
            v += countSize(c)
        return v
        
    def hasx(expr):
        res = False
        if expr == x: return True
        for c in expr.children():
            res = res | hasx(c)
        return res
        
        
    longest = 0
    longestKey = -1
    for inp in constantMap:
        e = constantMap[inp]
        l = countSize(e)
        if not hasx(e): continue
        if l > longest:
            longest = l
            longestKey = inp
            
    s = Solver()
    for k in reverseMap:
        s.add(reverseMap[k] == k)

    printToSolution("=L="+str(constantMap[longestKey]))
    s.add(constantMap[longestKey] == 0)
    if s.check() == sat:
        m = s.model()

        output = m[x].as_long().to_bytes(16, "little").hex()
        printToSolution("=R= "+output)

        printToSolution("=V= "+subprocess.check_output('echo -n '+output+' | xxd -r -p | ./rev_mvms/'+binaryName, shell=True, text=True).split("\n")[1])
    else:
        printToSolution("=R= UNSAT")
        
        
for i in range(max(1, startCount), min(endCount, 2000)):
    processBinary(i)