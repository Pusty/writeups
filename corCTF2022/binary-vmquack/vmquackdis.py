TYPE_IMM  = "imm" # size, letter
TYPE_REG    = "reg" # size, letter
TYPE_PCOFFSET = "pcoffset" # size, letter

convInst = [

('MOV.UPPER Rd, #i:16', 0, [(TYPE_REG, 8, 'd'), (TYPE_IMM, 16, 'i')]),
('LEA Rd, [#i:16]', 1, [(TYPE_REG, 8, 'd'), (TYPE_PCOFFSET, 16, 'i')]),
('CALL #o:32', 2, [(TYPE_PCOFFSET, 32, 'o')]),
('JMP #o:32', 3, [(TYPE_PCOFFSET, 32, 'o')]),
('CALL Rs+#o:16', 4, [(TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'o')]),
('JMP Rs+#o:16', 5, [(TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'o')]),
('J.E Ra, Rb, #o:16', 6, [(TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b'), (TYPE_PCOFFSET, 16, 'o')]),
('J.NE Ra, Rb, #o:16', 7, [(TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b'), (TYPE_PCOFFSET, 16, 'o')]),
('J.L Ra, Rb, #o:16', 8, [(TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b'), (TYPE_PCOFFSET, 16, 'o')]),
('J.GE Ra, Rb, #o:16', 9, [(TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b'), (TYPE_PCOFFSET, 16, 'o')]),
('J.B Ra, Rb, #o:16', 0xA, [(TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b'), (TYPE_PCOFFSET, 16, 'o')]),
('J.AE Ra, Rb, #o:16', 0xB, [(TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b'), (TYPE_PCOFFSET, 16, 'o')]),
('LDR.SB Rd, [Rs+#i:16]', 0xC, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('LDR.SW Rd, [Rs+#i:16]', 0xD, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('LDR.SD Rd, [Rs+#i:16]', 0xE, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('LDR.Q Rd, [Rs+#i:16]', 0xF, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('STR.B Rs, [Rd+#i:16]', 0x10, [(TYPE_REG, 8, 's'), (TYPE_REG, 8, 'd'), (TYPE_IMM, 16, 'i')]),
('STR.W Rs, [Rd+#i:16]', 0x11, [(TYPE_REG, 8, 's'), (TYPE_REG, 8, 'd'), (TYPE_IMM, 16, 'i')]),
('STR.D Rs, [Rd+#i:16]', 0x12, [(TYPE_REG, 8, 's'), (TYPE_REG, 8, 'd'), (TYPE_IMM, 16, 'i')]),
('STR.Q Rs, [Rd+#i:16]', 0x13, [(TYPE_REG, 8, 's'), (TYPE_REG, 8, 'd'), (TYPE_IMM, 16, 'i')]),
('LDR.B Rd, [Rs+#i:16]', 0x14, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('LDR.W Rd, [Rs+#i:16]', 0x15, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('LDR.D Rd, [Rs+#i:16]', 0x16, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('MOV.SB Rd, Rs', 0x17, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's')]),
('MOV.SW Rd, Rs', 0x18, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's')]),
('MOV.SD Rd, Rs', 0x19, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's')]),
('MOV.B Rd, Rs', 0x1A, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's')]),
('MOV.W Rd, Rs', 0x1B, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's')]),
('MOV.D Rd, Rs', 0x1C, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's')]),
('AND Rd, Ra, Rb', 0x1D, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('OR Rd, Ra, Rb', 0x1E, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('XOR Rd, Ra, Rb', 0x1F, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('AND Rd, Rs, #i:16', 0x20, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('OR Rd, Rs, #i:16', 0x21, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('XOR Rd, Rs, #i:16', 0x22, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),

('SHL Rd, Ra, Rb', 0x23, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('SHR Rd, Ra, Rb', 0x24, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('SAR Rd, Ra, Rb', 0x25, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('SHL Rd, Rs, #i:16', 0x26, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('SHR Rd, Rs, #i:16', 0x27, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('SAR Rd, Rs, #i:16', 0x28, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('CMP.L Rd, Ra, Rb', 0x29, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('CMP.B Rd, Ra, Rb', 0x2A, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('CMP.L Rd, Rs, #i:16', 0x2B, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('CMP.B Rd, Rs, #i:16', 0x2C, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('ADD Rd, Ra, Rb', 0x2D, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('SUB Rd, Ra, Rb', 0x2E, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('ADD Rd, Rs, #i:16', 0x2F, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 's'), (TYPE_IMM, 16, 'i')]),
('ADD.UPPER Rd, #i:16', 0x30, [(TYPE_REG, 8, 'd'),  (TYPE_IMM, 16, 'i')]),
('I.MUL Rd:Rq, Ra, Rb', 0x31, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'q'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('U.MUL Rd:Rq, Ra, Rb', 0x32, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'q'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('I.DIV Rd:Rq, Ra, Rb', 0x33, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'q'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('U.DIV Rd:Rq, Ra, Rb', 0x34, [(TYPE_REG, 8, 'd'), (TYPE_REG, 8, 'q'), (TYPE_REG, 8, 'a'), (TYPE_REG, 8, 'b')]),
('SYSCALL', 0x35, []),
('EXTCALL', 0x36, []),
]


def tryToParse2(data, inst):
    match = {}
    bi = 0
    if data[0] != inst[1]: return None, 0
    curIndx = 1
    for t in inst[2]:
        size = t[1]//8
        v = 0
        for i in range(size):
            v = v | (((data[curIndx+i])&0xff) << (i*8))
        curIndx += size 
        match[t[2]] = v

    return (match, 5)
    

def tryToParse(data):
    for inst in convInst:
        m, size = tryToParse2(data, inst)
        if m != None:
            return (inst, size, m)
    return (None, None, None)