gdb.execute("b *main") # break somewhere
gdb.execute("b *check_flag+35") # beginning of rol code
gdb.execute("b *check_flag+1330") # compare at the end
gdb.execute("run") # start the process


d = {} # dictionary of "encoded" values

for c in "0123456789": # iterate over all number character
    gdb.execute("jump *check_flag") # start the function
    gdb.execute("set *((int*)($ebp-0x1C)) = 0") # reset the index just in case
    gdb.execute("p flag_buf@1 = 0x%02X" % ord(c)) # set the first buffer character
    gdb.execute("continue") # encode the character
    v1 = int(gdb.parse_and_eval("$al"))&0xFF # read the encoded value
    d[v1] = c # save input and output character in a dictionary

res = [] # array containing finished number

for i in range(0x13):
    cmp = int(gdb.parse_and_eval("*((unsigned char*)(check_buf + "+str(i)+"))")) # check buffer value for the given index
    res.append(d[cmp]) # map the "encoded" value to a number

print("PCTF{%s}" % ''.join(res)) # PCTF{2052419606511006177}