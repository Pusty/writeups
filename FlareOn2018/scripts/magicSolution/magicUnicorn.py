from unicorn import *
from unicorn.x86_const import *
import struct
import string
import itertools

bruteForce =  string.printable
bruteForceLight =  string.ascii_lowercase+" .,"


rainbowTable = []

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000,0x10000)
mu.mem_map(0x7fff0000,0x10000)


def printDebug(s):
    print('\033[93m'+s)

tracedInstructions = 0
def traceCode(uc, address, size, user_data):
    global tracedInstructions
    tracedInstructions += 1
    

mu.hook_add(UC_HOOK_CODE, traceCode, None, 0x400000, 0x400000+0x10000)


def readRainbow():
    f = open("magicRainbowTable.txt")
    content = f.read().split("\n")
    for c in content:
        if len(c.split("#")) > 0:
            rainbowTable.append((int(c.split("#")[0],10),c.split("#")[1]+c.split("#")[2]+c.split("#")[3]))
    f.close()
    
def checkRainbow(value):
    possible = []
    printDebug(str(value))
    for p in rainbowTable:
        if p[0] == value or p[0] == (-(value))&0xFFFFFFFF:
            possible.append(p[1])
            
    if len(possible) > 0:
        printDebug("Rainbow found possible match!")
    return possible
    

def getFunction(addr):
    printDebug("x/2096b "+(hex(addr)[:-1]))
    byteA = gdb.execute("x/2096b "+(hex(addr)[:-1]), False, True)
    byteB = ''.join(map(chr, sum([[int(b, 16)&0xFF  for b in a.split("\t")[1:]] for a in byteA.split("\n")], [])))
    return byteB
    
def getValues(addr, amount):
    printDebug("x/"+str(amount)+"a "+(hex(addr)[:-1]))
    byteA = gdb.execute("x/"+str(amount)+"a "+(hex(addr)[:-1]), False, True)
    byteB = sum([[int(b, 16)  for b in a.split("\t")[1:]] for a in byteA.split("\n")], [])
    return byteB
    
def executeVM(addr, func, length, values, chars):
    global tracedInstructions
    mu.mem_write(0x7fff0000, "\x00"*0x10000)
    mu.mem_write(addr, func)
    tracedInstructions = 0
    for i in range(length):
        mu.mem_write(0x7fff0000+i, chars[i])
    for i in range(len(values)):
        mu.mem_write(0x7fff1000+8*i, struct.pack("Q",values[i]))
    mu.reg_write(UC_X86_REG_RSI, length)
    mu.reg_write(UC_X86_REG_RDX, 0x7fff1000)
    mu.reg_write(UC_X86_REG_RDI, 0x7fff0000)
    mu.reg_write(UC_X86_REG_RSP, 0x7fffe000)
    mu.mem_write(0x7fffe000, '\x01\x00\x00\x00')
    try:
        mu.emu_start(addr, 0)
    except Exception as e:
        if mu.reg_read(UC_X86_REG_RIP) == 1:
            r = mu.reg_read(UC_X86_REG_RAX)
            if r != 0:
                return 0
        else:
            printDebug(hex(mu.reg_read(UC_X86_REG_RIP)))
            printDebug(hex(mu.reg_read(UC_X86_REG_RSP)))
            printDebug(hex(mu.reg_read(UC_X86_REG_RBP)))
            raise e 
    return tracedInstructions

def executeFunction(addr, func, length, values):    
    base = ['_']*length
    
    if length > 0:
        for i in range(length-1):
            cTime = 0
            cChar = '_'
            for c in bruteForce:
                base[i] = c
                r = executeVM(addr, func, length, values, base)
                if r == -1: continue
                if(r > cTime):
                    cTime = r
                    cChar = c
            base[i] = cChar
    
    cTimeS = 0xffffffff
    cCharS = '_'
    cTimeB = 0
    cCharB = '_'
    for c in bruteForce:
        base[length-1] = c
        r = executeVM(addr, func, length, values, base)
        if r == -1: continue
        if(r < cTimeS):
            cTimeS = r
            cCharS = c
        if(r > cTimeB):
            cTimeB = r
            cCharB = c
    
    base[length-1] = cCharS
    if(executeVM(addr, func, length, values, base) == 0):
               printDebug("Found: "+''.join(base))
               return ''.join(base)
               
    base[length-1] = cCharB
    if(executeVM(addr, func, length, values, base) == 0):
               printDebug("Found: "+''.join(base))
               return ''.join(base)

    if length == 3:
        rainB = checkRainbow(values[0])
        for r in rainB:
            if executeVM(addr, func, length, values, list(r)) == 0:
                printDebug("Found: "+r)
                return r       
        
    
    printDebug("Going to run Unicorn ~"+str(len(bruteForceLight)**length)+" times...")
    
    if length == 1:
        for c1 in bruteForceLight:
            if executeVM(addr, func, length, values, [c1]) == 0:
                printDebug("Found: "+c1)
                return c1     
    if length == 2:
        for c1 in bruteForceLight:
            for c2 in bruteForceLight:
                if executeVM(addr, func, length, values, [c1,c2]) == 0:
                   printDebug("Found: "+c1+c2)
                   return c1+c2
                   
    if length == 3:
        for c1 in bruteForceLight:
            for c2 in bruteForceLight:
                for c3 in bruteForceLight:
                    if executeVM(addr, func, length, values, [c1,c2,c3]) == 0:
                       printDebug("Found: "+c1+c2+c3)
                       return c1+c2+c3
                       
    printDebug("Going to run Unicorn ~"+str(len(bruteForce)**length)+" times...")
    
    if length == 1:
        for c1 in bruteForce:
            if executeVM(addr, func, length, values, [c1]) == 0:
                printDebug("Found: "+c1)
                return c1     
    if length == 2:
        for c1 in bruteForce:
            for c2 in bruteForce:
                if executeVM(addr, func, length, values, [c1,c2]) == 0:
                   printDebug("Found: "+c1+c2)
                   return c1+c2         
                   
    """
    if length == 3:
        for c1 in bruteForce:
            for c2 in bruteForce:
                for c3 in bruteForce:
                    if executeVM(addr, func, length, values, [c1,c2,c3]) == 0:
                       printDebug("Found: "+c1+c2+c3)
                       return c1+c2+c3
    """
        
    return None
    
gdb.execute("set pagination off") #Sets up GDB
gdb.execute("d") 

gdb.execute("b *0x402e25") #check for length (required len in rax)
gdb.execute("b *0x402f06") #call rcx (new function) with rdi=address to key at offset, esi=amount of characters, rdx=address of compare values
gdb.execute("b *0x402f08") #here the result is compared, to cheat just set eax = 1
gdb.execute("b *0x403B62") #beat trial

already = "_"*128
currentRun = 0
password = list(already)

readRainbow()

f = open("tmp", "w")
for i in range(666):
    f.write("_"*128+"\n")
f.close()
    
gdb.execute("run < tmp")

while True:
    pos = long(gdb.parse_and_eval("$rip"))
    if pos == 0x402e25:
        min_len = long(gdb.parse_and_eval("$rax"))
        gdb.execute("set *((int*)($rbp-0x20)) = 128")
        gdb.execute("continue")
    elif pos == 0x402f06:  
        func_addr = long(gdb.parse_and_eval("$rcx"))
        amount    = int(gdb.parse_and_eval("$esi"))
        compare   = long(gdb.parse_and_eval("$rdx"))
        printDebug("Calling "+hex(func_addr)+" to verify "+str(amount)+" characters")
        not_ready = True
        start_index = min_len-amount
        for i in range(amount):
            if(already[start_index+i] != '_'):
                not_ready = False
           
        if amount < 4 and currentIndex <= currentRun:
            array = getFunction(func_addr)
            values = getValues(compare, amount)
            result = executeFunction(func_addr, array, amount, values)
            if result == None:
                printDebug("Bruteforce failed")
            else:
                printDebug(result)
                for i in range(len(result)):
                    password[start_index+i] = result[i]
                printDebug(''.join(password))
        gdb.execute("continue")
    elif pos == 0x402f08:
        gdb.execute("set $rax = 1")
        gdb.execute("continue")
    elif pos == 0x403B62:
        printDebug("Next Level!")
        if currentIndex <= currentRun: 
            f = open("flags/magicFlag"+str(currentRun)+".txt", "wb")
            f.write(''.join(password))
            f.close()
        already = "_"*128
        password = list(already) 
        gdb.execute("continue")
        
        currentRun +=1