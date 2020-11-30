opcodes = [ ("ADD", 3), 
            ("AGETV", 16), 
            ("AND", 7), 
            ("APUTV", 17), 
            ("ARGC", 53), 
            ("BF", 41), 
            ("BPUSH", 43), 
            ("BT", 40), 
            ("CANHAZPLZ", 34), 
            ("CPUSH", 52), 
            ("DIV", 6), 
            ("DPUSH", 50), 
            ("DUP", 46), 
            ("EQ", 26), 
            ("FPUSH", 38), 
            ("FRPUSH", 42), 
            ("GETM", 48), 
            ("GETV", 13), 
            ("GOTO", 25), 
            ("GT", 29), 
            ("GTE", 30), 
            ("INCSP", 1), 
            ("INV", 45), 
            ("INVOKE", 15), 
            ("IPUSH", 37), 
            ("ISA", 33), 
            ("ISNULL", 32), 
            ("JSR", 35), 
            ("LGETV", 18), 
            ("LPUSH", 49), 
            ("LPUTV", 19), 
            ("LT", 27), 
            ("LTE", 28), 
            ("MOD", 9), 
            ("MUL", 5), 
            ("NE", 31), 
            ("NEWA", 20), 
            ("NEWBA", 54), 
            ("NEWC", 21), 
            ("NEWD", 47), 
            ("NEWS", 24), 
            ("NOP", 0), 
            ("NPUSH", 44), 
            ("OR", 8), 
            ("POPV", 2), 
            ("PUTV", 14), 
            ("RET", 23), 
            ("RETURN", 22), 
            ("SHL", 10), 
            ("SHR", 11), 
            ("SPUSH", 39), 
            ("SUB", 4), 
            ("THROW", 51), 
            ("TS", 36), 
            ("XOR", 12)
          ]


def getSize(op):
    opcode = op[1]
    if opcode == 1 or opcode == 10 or opcode == 11 or opcode == 15 or opcode == 18 or opcode == 19 or opcode == 43 or opcode == 46 or opcode == 53: return 2
    if opcode == 24 or opcode == 37 or opcode == 38 or opcode == 39 or opcode == 52: return 5
    if opcode == 25 or opcode == 35 or opcode == 40 or opcode == 41: return 3
    if opcode == 49 or opcode == 50: return 9
    return 1
    
def findOpcode(opcode):
    for code in opcodes:
        if code[1] == opcode:
            return code
    return None
    
def disassemble(data):
    opcode = ord(data[0])
    code = findOpcode(opcode)
    if code == None: return ("ILLEGAL", 1)
    size = getSize(code)
    return (code[0], size)

    
    
f = open("hitcon.prg", "rb")
data = f.read()
f.close()

data = data[data.index("c0debabe".decode("hex")):] # find code base
data = data[8:] # ignore header and size field


dis, next = disassemble(data)


pc = 268435456 # as per ciqdb Code Table

while dis != "ILLEGAL":
    # as per ciqdb Code Table
    if pc == 268435554: print("initialize:")
    if pc == 268435611: print("onLayout:")
    if pc == 268435636: print("onUpdate:")
    if pc == 268435913: print("timerCallback:")
    if pc == 268435953: print("solve:")
    if pc == 268436065: print("drawFlag:")
    if pc >= 268435554 and pc <= 268436191:
        print("   "+hex(pc)+": "+dis+" "+data[1:next].encode("hex"))
    data = data[next:]
    pc = pc + next
    dis, next = disassemble(data)


