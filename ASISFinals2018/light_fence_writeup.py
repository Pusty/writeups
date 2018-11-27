#break before actual code execution
gdb.execute("b getopt")
gdb.execute("b exit") #2nd breakpoint for doing it in one run
#prevent files from being deleted
gdb.execute("b unlink")

gdb.execute("run -e filler") #execute with filler

#write array list to given address
def writeBuffer(addr, content):
    for i in range(len(content)):
        gdb.execute("set *((unsigned char*)("+hex(addr).replace("L","")+"+"+str(i)+")) = "+str(content[i]&0xFF))
    return addr

#call sub_14A0 with nsgName and outputName
def densgFile(base_addr, nameIn, nameOut):
    nsgAddr = base_addr + 0x14A0
    nameIn = [ord(c) for c in nameIn]+[0]
    nameOut = [ord(c) for c in nameOut]+[0]
    nameInAddr = writeBuffer(stack-0x100, nameIn)
    nameOutAddr = writeBuffer(stack-0x200, nameOut)
    gdb.execute("set $rdi = "+hex(nameInAddr).replace("L",""))
    gdb.execute("set $rsi = "+hex(nameOutAddr).replace("L",""))
    gdb.execute("jump *"+hex(nsgAddr).replace("L",""))
    gdb.execute("c")
    
#split .enc file in 260 bytes table and "huff" file
def splitEnc(filename):
    f = open(filename, "rb")
    d = f.read()
    f.close()
    fp1 = open(filename+".p1", "wb")
    fp1.write(d[:0x104])
    fp1.close()
    fp2 = open(filename+".p2", "wb")
    fp2.write(d[0x104:])
    fp2.close()
    
#call sub_18A0 with the "huff" file, output file and content of the 260 byte table
def dehuff(base_addr, filep, fileOut):
    splitEnc(filep)
    nsgAddr = base_addr + 0x18A0
    nameIn = [ord(c) for c in filep+".p2"]+[0]
    nameOut = [ord(c) for c in fileOut]+[0]
    dataBuf = [ord(c) for c in open(filep+".p1", "rb").read()]+[0]
    nameInAddr = writeBuffer(stack-0x4100, nameIn)
    nameOutAddr = writeBuffer(stack-0x4200, nameOut)
    dataBufAddr = writeBuffer(stack-0x4300-len(dataBuf), dataBuf)
    gdb.execute("set $rdi = "+hex(nameInAddr).replace("L",""))
    gdb.execute("set $rsi = "+hex(nameOutAddr).replace("L",""))
    gdb.execute("set $rdx = "+hex(dataBufAddr+4).replace("L","")) #4 byte offset, not really sure why
    gdb.execute("jump *"+hex(nsgAddr).replace("L",""))
    gdb.execute("c")
    
    
#save stack address to have a place to store data at
stack = long(gdb.parse_and_eval("$rsp"))

#set a breakpoint at the return point
return_addr = long(gdb.parse_and_eval("*((void**)$rsp)"))
gdb.execute("b *"+(hex(return_addr).replace("L","")))
#also use the return point to calculate the base of the binary
base_addr = return_addr-0xB42
#undo the "enc" and "huff" steps by first splitting the file and then running the "huff" undo function
dehuff(base_addr, "flag.enc", "flag.nsg")
#again break after execution is done
return_addr = long(gdb.parse_and_eval("*((void**)$rsp)"))
gdb.execute("b *"+(hex(return_addr).replace("L","")))
#undo the "nsg" step and return the flag in its original state
densgFile(base_addr, "flag.nsg", "flag")
gdb.execute("set confirm off")
gdb.execute("quit")