# Light Fence 

```
light_fence.elf: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=2a3895fbfcb14e507c5ac348982b177beab26d2f, stripped
```

light_fence.elf is a binary that requires an option (either -e or -d) and a associated file to work:
 - Using the -e option the binary creates a new file that contains the original data in an encoded format
 - Using the -d option the binary outputs "Not implemented yet!"

Besides the binary the challenge contains a file named "flag.enc" with the task to decode it.

## Solution

Looking into the encoding process by stopping the binary before it deletes its temporary files reveals that the encoding process is structured into 3 steps, first the file is scrambled and saved in a "nsg" file, after that a "huff" file and lastly a "enc" file is generated that further encode the content.
The last step actually just puts a 260 bytes structure before appending the content of the "huff" file to the "enc" file, which means that we can recreate the "huff" file from the "enc" file.

Actually the binary is lying to us when it says that the decoding is not implemented yet because it contains all the needed functionality to do so in it, it's just not referenced anywhere:
    - sub_18A0 contains the code to undo the "enc" and "huff" steps
    - sub_14A0 contains the code to undo the "nsg" step and gives out the decoded file

For properly calling sub_18A0 the function needs the "huff" file name, the output file name and a pointer to the 260 bytes structure at the beginning of the "enc" file.
The sub_14A0 just needs the "nsg" file name and again a output file name.

There are multiple ways of solving this but I just plainly reused the binary with a gdb python script to call those functions:

```python
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
```

```
gdb --command light_fence_writeup.py light_fence.elf && cat flag
```

```                                       
           _    ____  _ _____  ___   ___ _______   
  ___ __ _| |__| ___|/ |___ / ( _ ) / _ \___  \ \  
 / __/ _` | '_ \___ \| | |_ \ / _ \| | | | / / | | 
| (_| (_| | |_) |__) | |___) | (_) | |_| |/ /   > >
 \___\__,_|_.__/____/|_|____/ \___/ \___//_/   | | 
                                              /_/  
    _    ____ ___ ____    _____      _     _  ___  _         _  __ _____ ___  
   / \  / ___|_ _/ ___|  / / _ \  __| | __| |/ _ \| |__   __| |/ _|___  / _ \ 
  / _ \ \___ \| |\___ \ | | | | |/ _` |/ _` | (_) | '_ \ / _` | |_   / / | | |
 / ___ \ ___) | | ___) < <| |_| | (_| | (_| |\__, | |_) | (_| |  _| / /| |_| |
/_/   \_\____/___|____/ | |\___/ \__,_|\__,_|  /_/|_.__/ \__,_|_|  /_/  \___/ 
                         \_\                                                  
 _  _  _____  __ _  _    ___  ___  _ ____ _____ _____ _  _    ___   ___   __   
| || ||___ / / _| || |  ( _ )/ _ \/ |___ \___  |___  | || |  / _ \ / _ \ / /_  
| || |_ |_ \| |_| || |_ / _ \ (_) | | __) | / /   / /| || |_| | | | | | | '_ \ 
|__   _|__) |  _|__   _| (_) \__, | |/ __/ / /   / / |__   _| |_| | |_| | (_) |
   |_||____/|_|    |_|  \___/  /_/|_|_____/_/   /_/     |_|  \___/ \___/ \___/ 
```