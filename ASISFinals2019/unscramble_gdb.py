import gdb

SQRT_VALUE = 109 # size root of the real flags file size
f = open("flag", "wb")
f.write(bytes([(i&0xFF) for i in range(SQRT_VALUE*SQRT_VALUE)])) # write some dummy values
f.close()

gdb.execute("d")
gdb.execute("break *rand")

gdb.execute("run")
gdb.execute("finish") # finish rand()
gdb.execute("set $rax = 0") # rand() = 0, for consistency  [0x555555556918]

gdb.execute("break *($rip+0x187)")  # here we can parse the original list [0x555555556a9f]
gdb.execute("continue")

# 00000000000023CA - scamble function
# 000000000000321D - read value, recursive structure  0x55555555721d
gdb.execute("break *($rip-0x6d5)") # scramble function     0x5555555563ca
gdb.execute("break *($rip+0x77e)") # here the values get read in shuffled order 0x55555555721d
gdb.execute("continue")

constBreakpoint = long(gdb.parse_and_eval("$rip")) # address of the scramble function

listOfLists = [] # list containing all recursive scrambling results

while constBreakpoint == long(gdb.parse_and_eval("$rip")):

    # Amount of vector<int>'s in the vector<vector<int>> used for the scramble call
    bufferStart = gdb.parse_and_eval("*((void**)($rsi))")
    bufferEnd   = gdb.parse_and_eval("*((void**)($rsi+8))")
    bufferSize  = int((bufferEnd-bufferStart)/(8*3))
    
    # If the list is empty scrambling is finished
    if bufferSize == 0: break
    
    # Save all addresses used to save values in the vector<int>'s
    contentMap = {}
    for i in range(SQRT_VALUE):
        startReading = long(gdb.parse_and_eval("*((void**)("+str(bufferStart)+"+"+str(0)+"))"))
        endReading   = long(gdb.parse_and_eval("*((void**)("+str(bufferStart)+"+"+str(8)+"))"))
        bufferStart = bufferStart + 8*3
        for x in range(bufferSize):
            contentMap[long(startReading)+x*4] = i*bufferSize+x # save the address and index

    print(contentMap)

    # Now record and save all accesses to the data and their sequence
    callList = []
    gdb.execute("continue") # continue from constructor
    for i in range(SQRT_VALUE*SQRT_VALUE):
        if constBreakpoint != long(gdb.parse_and_eval("$rip")):
            currentAccess = long(gdb.parse_and_eval("$rax"))
            callList.append(contentMap[currentAccess]) # add the original index
            gdb.execute("continue") # next
 
    print([hex(x) for x in callList]) # output the result of this scrambling iteration in readable format
    listOfLists.append(callList)      # append it to the list of recursive scrambling

print(listOfLists)

# iterate backwards through the lists and apply the recursive scrambling on the lists it applies to
for i in range(len(listOfLists)-1):
    cL = listOfLists[-i-1]
    tL = listOfLists[-i-2][-len(cL)::]
    listOfLists[-i-2] = listOfLists[-i-2][:-len(cL)]+[tL[cL[j]] for j in range(len(cL))]
    
print([hex(x) for x in listOfLists[0]]) # output the final scrambling format
gdb.execute("continue")                 # let it write the "flag.enc" file for confirming it worked