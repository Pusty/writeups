gdb.execute("set pagination off")
gdb.execute("set confirm off")

version = 0 # 0 - 15 (split so running multiple instances parallel is possible)

# create a dummy file to encrypt
dummyFile = open("test%d.txt" % version, "w")
dummyFile.write("D"*0x2F)
dummyFile.close()

# some initial code to set the breakpoints in a position independent environment
gdb.execute("b *rand") # break at rand
gdb.execute("run") # run until rand
gdb.execute("finish") # continue until the function ends
gdb.execute("delete") # delete all breakpoints

gdb.execute("b") # set a breakpoint after the random value to modify it [0000000000002DCF]
ip = int(gdb.parse_and_eval("$rip"))
gdb.execute("b *0x%X" % (ip + 0x73a)) # read rdx from here to get value for the key [0000000000003509]


for index in range(max(1,0x1000*version), 0x1000*(version+1))): # skip 0 as it crashes the binary
    gdb.execute("set logging redirect off")
    print("%04X" % index)
    gdb.execute("set logging redirect on")
    gdb.execute("run test%d.txt" % version) # start the process

    # modify random

    gdb.execute("set $rax = "+hex(index))
    gdb.execute("continue")

    solMap = []

    for i in range(0x2F):
        solMap.append(int(gdb.parse_and_eval("$rdx"))&0xFF)
        gdb.execute("continue")
        
    f = open("./rnums/entry_%04X.txt" % (index),"w")
    f.write(str(solMap))
    f.close()