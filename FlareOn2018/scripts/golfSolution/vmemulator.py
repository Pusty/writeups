#flare-on challenge 10 VM

import struct

REG_0 = 8*0
REG_1 = 8*1
REG_2 = 8*2
REG_3 = 8*3
REG_4 = 8*4
REG_5 = 8*5
REG_6 = 8*6
REG_7 = 8*7
REG_8 = 8*8
REG_9 = 8*9
REG_10 = 8*10
REG_11 = 8*11
REG_12 = 8*12
REG_13 = 8*13
REG_14 = 8*14
REG_15 = 8*15

def processReg(reg):
    if reg == 0xF4:
        print("Trying to process register 0xF4 *special case*")
        return -1
    if reg == 0xEE: return REG_15
    if reg == 0xF0: return REG_14
    if reg == 0xF1: return REG_13
    if reg == 0xEF: return REG_12
    if reg == 0xF5: return REG_11
    if reg == 0xF6: return REG_10
    if reg == 0xF2: return REG_9
    if reg == 0xF3: return REG_8
    if reg == 0xF7: return REG_7
    if reg == 0xF8: return REG_6
    if reg == 0xF9: return REG_5
    if reg == 0xFA: return REG_4
    if reg == 0xFB: return REG_3
    if reg == 0xFC: return REG_2
    if reg == 0xFD: return REG_1
    if reg == 0xFE: return REG_0
    #print("? Illegal Register Found "+hex(reg))
    return -1
    
def processReg2(reg):
    if reg == 0xEB:
        print("Trying to process register 0xEB *special case*")
        return -1
    reg = reg + 9
    if reg == 0xEE: return REG_15
    if reg == 0xF0: return REG_14
    if reg == 0xF1: return REG_13
    if reg == 0xEF: return REG_12
    if reg == 0xF5: return REG_11
    if reg == 0xF6: return REG_10
    if reg == 0xF2: return REG_9
    if reg == 0xF3: return REG_8
    #print("? Illegal Register Found "+hex(reg))
    return -1

f = open("code1.bin","rb") #code1.bin or code2.bin or code3.bin or code4.bin
code = f.read()
f.close()


ip = 0
flags = 0
memory = [0]*1000

memory[REG_11] = 500

#part1
"""memory[0] = ord("F")
memory[1] = ord("l")
memory[2] = ord("4")
memory[3] = ord("R")
memory[4] = ord("3")"""
# c0+c1+c2+c3+c4 == 0x16b, c0 = "F", c4 = "3",  c2+c3 == 0x86, c1+c2 == 0xa0

"""
Solution for 1
>>> from z3 import *
>>> c = [BitVec("c"+str(i), 8) for i in range(5)]
>>> s = Solver()
>>> s.add(c[0]+c[1]+c[2]+c[3]+c[4] == 0x16b)
>>> s.add(c[0] == ord('F'))
>>> s.add(c[4] == ord('3'))
>>> s.add(c[2]+c[3] == 0x86)
>>> s.add(c[1]+c[2] == 0xA0)
>>> s.check()
sat
>>> s.model()
[c3 = 82, c4 = 51, c0 = 70, c1 = 108, c2 = 52]
"""

#part2
"""memory[0] = ord("w")
memory[1] = ord("1")
memory[2] = ord("t")
memory[3] = ord("h")
memory[4] = ord("_")
"""

"""
memory[0]^0x80^0x52 == 0xa5
memory[1]^0xd2^0x52 == 0xb1
memory[2]^0x24^0x52 == 0x02
memory[3]^0x76^0x52 == 0x4c
memory[4]^0xc8^0x52 == 0xc5
"""

#part2
#Register 11 += 0x28 = 0x1f4


#part3 (xor all with 0x75 and compare)
"""
memory[0] = ord("u")
memory[1] = ord("r")
memory[2] = ord("_")
memory[3] = ord("v")
memory[4] = ord("1")
memory[5] = ord("s")
memory[6] = ord("0")
memory[7] = ord("r")
memory[8] = ord("_")
"""

#part4
"""
memory[0] = ord("W")
memory[1] = ord("e")
memory[2] = ord("4")
memory[3] = ord("r")
memory[4] = ord("_")
"""

#We4r_ur_v1s0r_w1th_Fl4R3@flare-on.com


while True: #memory[REG_11]
    if len(code) <= ip or ip < 0:
        print("Reached End..")
        break
    opcode = struct.unpack("<B", code[ip:ip+1])[0]
    #print("["+hex(ip)+"] "+hex(opcode))
    if opcode == 0x01:
        print("Sucessful Run!")
        break
    if opcode == 0xE2:
        print("Not executable memory reached..")
        break
    elif opcode == 0x02: #mov
        reg, reg2 = struct.unpack("<BB", code[ip+1:ip+3])
        regAddr = processReg2(reg2)
        regAddr2 = processReg2(reg)
        print("* Register "+str(regAddr/8)+" = Register "+str(regAddr2/8))
        memory[regAddr] = memory[regAddr2]
        ip += 3
    elif opcode == 0xD5: #mov
        reg, reg2 = struct.unpack("<BB", code[ip+1:ip+3])
        regAddr = processReg2(reg)
        regAddr2 = processReg2(reg2)
        print("* Register "+str(regAddr/8)+" ^= Register "+str(regAddr2/8)+" = "+hex(memory[regAddr] ^ memory[regAddr2]))
        memory[regAddr] ^= memory[regAddr2]
        ip += 3
    elif opcode == 0x19:
        reg, mem = struct.unpack("<BI", code[ip+1:ip+6])
        print("* Loading "+hex(memory[memory[REG_11]+mem])+"["+str(memory[REG_11]+mem)+"] into Register "+str(processReg2(reg)/8))
        memory[processReg2(reg)] = memory[memory[REG_11]+mem]
        ip += 6
    elif opcode == 0x1A: #load from memory
        reg, mem = struct.unpack("<BI", code[ip+1:ip+6])
        print("* Loading "+hex(memory[memory[REG_11]+mem])+"["+str(memory[REG_11]+mem)+"] into Register "+str(processReg(reg)/8))
        memory[processReg(reg)] = memory[memory[REG_11]+mem]
        ip += 6
    elif opcode == 0x17:
        mem = struct.unpack("<I", code[ip+1:ip+5])[0]
        print("* Loading Register 15  into "+hex(memory[memory[REG_11]+mem]&0xFF)+"["+str(memory[REG_11]+mem)+"] [!]")
        memory[memory[REG_11]+mem] = memory[REG_15]&0xFF
        ip += 5
    elif opcode == 0x1B:
        mem = struct.unpack("<I", code[ip+1:ip+5])[0]
        print("* Loading "+hex(memory[memory[REG_11]+mem]&0xFF)+"["+str(memory[REG_11]+mem)+"] into Register 15 [!]")
        memory[REG_15] = memory[memory[REG_11]+mem]&0xFF
        ip += 5
    elif opcode == 0xC1 or opcode == 0xC3: #add/sub reg
        if opcode == 0xC1:
            mode = 1
        else:
            mode = -1
        reg, mem = struct.unpack("<BI", code[ip+1:ip+6])
        regAddr = processReg(reg)
        #if regAddr == REG_11:
        #    print("C1/C3 REG=REG_11 case not implemented")
        if opcode == 0xC1:
            print("* Register "+str(regAddr/8)+" += "+hex(mem)+" = "+hex(memory[regAddr] + mem*mode))
        else:
            print("* Register "+str(regAddr/8)+" -= "+hex(mem)+" = "+hex(memory[regAddr] + mem*mode))
        memory[regAddr] = memory[regAddr] + mem*mode
        ip += 6
    elif opcode == 0xD8: #mov
        reg, mem = struct.unpack("<BI", code[ip+1:ip+6])
        print("* Loading "+hex(memory[processReg2(reg)])+"(Register "+str(processReg2(reg)/8)+") into ["+str(memory[REG_11]+mem)+"]")
        memory[memory[REG_11]+mem] = memory[processReg2(reg)]
        ip += 6
    elif opcode == 0xD1 or opcode == 0xD3: #add/sub reg
        if opcode == 0xD1:
            mode = 1
        else:
            mode = -1
        reg, mem = struct.unpack("<BI", code[ip+1:ip+6])
        regAddr = processReg2(reg)
        #if regAddr == REG_11:
        #    print("C1/C3 REG=REG_11 case not implemented")
        if opcode == 0xC1:
            print("* Register "+str(regAddr/8)+" += "+hex(mem)+" = "+hex(memory[regAddr] + mem*mode))
        else:
            print("* Register "+str(regAddr/8)+" -= "+hex(mem)+" = "+hex(memory[regAddr] + mem*mode))
        memory[regAddr] = memory[regAddr] + mem*mode
        ip += 6
    elif opcode == 0xD2 or opcode == 0xD4: #add/sub reg
        if opcode == 0xD2:
            mode = 1
        else:
            mode = -1
        reg, reg2 = struct.unpack("<BB", code[ip+1:ip+3])
        regAddr = processReg2(reg2)
        regAddr2 = processReg2(reg)
        #if regAddr == REG_11:
        #    print("C1/C3 REG=REG_11 case not implemented")
        if opcode == 0xD2:
            print("* Register "+str(regAddr/8)+" += Register "+str(regAddr2/8)+" = "+hex(memory[regAddr] + memory[regAddr2]*mode))
        else:
            print("* Register "+str(regAddr/8)+" -= Register "+str(regAddr2/8)+" = "+hex(memory[regAddr] + memory[regAddr2]*mode))
        memory[regAddr] = memory[regAddr] + memory[regAddr2]*mode
        ip += 3
    elif opcode == 0xC0: #xor with constant
        reg, const = struct.unpack("<BI", code[ip+1:ip+6])
        print("* Xor Register "+str(processReg2(reg)/8)+" with "+hex(const)+"(Const) = "+hex(memory[processReg2(reg)]^const))
        memory[processReg2(reg)] ^= const
        ip += 6
    elif opcode == 0xC8: #save to memory
        reg, mem = struct.unpack("<BI", code[ip+1:ip+6])
        print("* Loading "+hex(memory[processReg(reg)])+"(Register "+str(processReg(reg)/8)+") into ["+str(memory[REG_11]+mem)+"]")
        memory[memory[REG_11]+mem] = memory[processReg(reg)]
        ip += 6
    elif opcode == 0xC9: #save constant
        mem, value = struct.unpack("<IQ", code[ip+1:ip+13])
        print("* Loading "+hex(value)+"(Const) into ["+str(memory[REG_11]+mem)+"]")
        #if value == 0 and memory[REG_11]+mem == 460: break #stop when error / return value 0
        memory[memory[REG_11]+mem] = value
        ip += 13
    elif opcode == 0x41: #set flags / compare
        reg, mem = struct.unpack("<BI", code[ip+1:ip+6])
        a = memory[processReg2(reg)]
        b = mem
        print("! Comparing "+hex(a)+"(Register "+str(processReg2(reg)/8)+") with "+hex(b)+"(Const)")
        if a == b:
            flags |= 0x40
        else:
            flags &= ~0x40
        ip += 6
    elif opcode == 0x42: #set flags / compare
        mem1, mem = struct.unpack("<II", code[ip+1:ip+9])
        a = memory[memory[REG_11]+mem1]
        b = mem
        print("! Comparing "+hex(a)+"["+str(memory[REG_11]+mem1)+"] with "+hex(b)+"(Const)")
        if a == b:
            flags |= 0x40
        else:
            flags &= ~0x40
        ip += 9
    elif opcode == 0x40: #set flags / compare
        reg1, reg2 = struct.unpack("<BB", code[ip+1:ip+3])
        a = memory[processReg2(reg1)]
        b = memory[processReg2(reg2)]
        print("! Comparing "+hex(a)+"(Register "+str(processReg2(reg1)/8)+") with "+hex(b)+"(Register "+str(processReg2(reg2)/8)+")")
        if a == b:
            flags |= 0x40
        else:
            flags &= ~0x40
        ip += 3
    elif opcode == 0x50: #fixed jump
        mem = struct.unpack("<h", code[ip+1:ip+3])[0]
        print("* Jumping")
        ip += mem
    elif opcode == 0x52: #jump zf/not zf
        t = struct.unpack("<H", code[ip+1:ip+3])[0]
        if(flags&0x40 > 0):
            print("* Jump True")
            ip = ip+t
        else:
            print("* Jump False")
            ip = ip+3
    elif opcode == 0x54: #jump ??
        t = struct.unpack("<h", code[ip+1:ip+3])[0]
        if(flags&0x40 > 0): # | (v3 = 0, v4 = flag == (flag >> 4), ((flag ^ (flag >> 4)) & 0x80u) == 0i64)
            print("* Jump True")
            ip = ip+t
        else:
            print("* Jump False")
            ip += 3
    elif opcode == 0x1D: #add memory
        reg1 = struct.unpack("<B", code[ip+1:ip+2])[0]
        tmpReg = processReg(reg1)
        address = 2
        size = 6
        while processReg(struct.unpack("<B", code[ip+address:ip+address+1])[0]) != -1:
            address += 1
            size += 1
        offset = memory[REG_11]+struct.unpack("<I", code[ip+address:ip+address+4])[0]
        print("* Loading "+hex(memory[offset])+"["+str(offset)+"] into Register "+str(tmpReg/8)+"")
        memory[tmpReg] = memory[offset]
        ip += size
    elif opcode == 0x1C:
        reg1 = struct.unpack("<B", code[ip+1:ip+2])[0]
        tmpReg = processReg2(reg1)
        added = 0
        address = 2
        size = 6
        while processReg(struct.unpack("<B", code[ip+address:ip+address+1])[0]) != -1:
            add = memory[processReg(struct.unpack("<B", code[ip+address:ip+address+1])[0])]
            print("         Adding "+hex(add)+" from Register "+str(processReg(struct.unpack("<B", code[ip+address:ip+address+1])[0])/8))
            added += add
            address += 1
            size += 1
        memory[tmpReg] = 0
        if opcode == 0x20:
            result = struct.unpack("<I", code[ip+address:ip+address+4])[0]+added
        else:
            result = memory[REG_11]+struct.unpack("<I", code[ip+address:ip+address+4])[0]+added
        print("* Loading "+hex(memory[result])+"["+str(result)+"] into Register "+str(tmpReg/8)+"")
        memory[tmpReg] = memory[result]
        ip += size
    elif opcode == 0x1E or opcode == 0x1F: #add memory
        reg1 = struct.unpack("<B", code[ip+1:ip+2])[0]
        tmpReg = processReg2(reg1)
        added = 0
        address = 2
        size = 6
        while processReg(struct.unpack("<B", code[ip+address:ip+address+1])[0]) != -1:
            add = memory[processReg(struct.unpack("<B", code[ip+address:ip+address+1])[0])]
            print("         Adding "+hex(add)+" from Register "+str(processReg(struct.unpack("<B", code[ip+address:ip+address+1])[0])/8))
            added += add
            address += 1
            size += 1
        if opcode == 0x1F:
            offset = struct.unpack("<I", code[ip+address:ip+address+4])[0]
        else:
            offset = memory[REG_11]+struct.unpack("<I", code[ip+address:ip+address+4])[0]
        print("* Loading "+hex(memory[offset+added])+"["+str(offset+added)+"] into Register "+str(tmpReg/8)+"")
        memory[tmpReg] = memory[offset+added]
        ip += size
    else:
        print("Unsupported Opcode: "+hex(opcode))
        break