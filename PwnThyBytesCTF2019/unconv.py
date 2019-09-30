# 1. Run ./unconventional
# 2. Figure out the pid of it
# 3. Attach gdb to it ("attach <pid>")
# 4. Enter a string into the terminal of the binary
# 5. "source unconv.py"

lastInst = ""
firstNop = False
interesting = False
f = open("trace.txt", "w") # open a file to output a trace

try:
    while True:
        curValue = int(gdb.parse_and_eval("*((unsigned char*)($rip))"))&0xFF # read the opcode of the current instruction
        curInst = gdb.execute("x/i $rip", to_string=True) # read the disassembly for the current instruction
        
        if curValue == 0x90: # if the instruction is the first "nop" after other instructions, the instruction executed before is the result of self modifying code
            if firstNop: 
                f.write(lastInst[3:])
            firstNop = False # not the first nop
        else:
            firstNop = True  # if a normal instruction is executed the instruction before the next nop is interesting
            
        if "fisttp" in lastInst:  # the jmp rax and other interesting instructions are getting executed after fisttp's
            interesting = True
         
        if ("mov" in curInst and "0x90" in curInst) or ("fi" in curInst) or ("fstp" in curInst):  #when these parts are in the current instruction then nothing interesting happens
            interesting = False
        
        if interesting:   # output jumps and in between instructions (some are not relevant, but more information is better)
            f.write(curInst[3:])

        lastInst = curInst
        gdb.execute("si")  # step to the next instruction
except Exception:
    pass # when the program ends an exception is thrown, ignore it and close the file
    
f.close()