import struct
import sys

f = open("BEFORE_EXECUTION.bin", "rb")
binary = f.read()
f.close()


def getValue(base_data, index):
    index = index&0xFFFF
    #if offset+index+1 >= len(base_data):
    #     index = -(0xffff-index+1)
    index = (offset+index)&0xFFFF
    if index >= 0x5E60 and index < 0x5ED0:
        print "reading password char "+hex(index)
    if index >= 0x142A and index < 0x146F:
        print "reading password char "+hex(index)
    """if index >= 0x121B and index < 0x143B:
        print "reading char "+hex(index)"""
    #print "Reading..."+hex(index)
    return struct.unpack("H", base_data[index]+base_data[(index+1)&0xFFFF])[0]&0xFFFF
    
def setValue(base_data, index, value):
    values = struct.pack("H", value&0xFFFF)
    index = index&0xFFFF
    #if offset+index+1 >= len(base_data):
    #     index = -(0xffff-index+1)
    #print "#"+hex(index) + " <- " +hex(value) #BP 9800:5DBE
    index = (index+offset)&0xFFFF
    """if index >= offset+0x4 and index < offset+0x10:
        print "writing char.."""
    base_data[index]     = values[0]
    base_data[(index+1)&0xFFFF] = values[1]

def evalInst(base_data, insp, word1, word2, word3):
    #print hex(word1 << 1)+" - "+hex(word2 << 1)+" - "+hex(word3)
    #print "Insp: "+hex(insp<<1)+" A: "+hex(word1 << 1)+" - B: "+hex(word2 << 1)
    sub_values = (getValue(base_data, word2 << 1) - getValue(base_data, word1 << 1))&0xFFFF
    setValue(base_data, word2 << 1, sub_values)
    if word3 == 0: return False
    if sub_values <= 0 or sub_values >= 0x7FFF: return True
    return False
    
def vmCode(base_data, offset_max, init_offset):
    instp = init_offset
    executed = -1
    while instp+3 < offset_max:
        executed += 1
        #print hex(instp) #BP 9800:5DEB
        shouldJump = evalInst(base_data, instp,getValue(base_data, instp << 1), getValue(base_data, (instp << 1)+2), getValue(base_data, (instp << 1)+4))
        if shouldJump == True:
            dest = getValue(base_data, (instp+2) << 1)&0xFFFF
            if dest == 0xFFFF: return
            instp = dest
        else:
            instp += 3
            instp = instp&0xFFFF
        if(getValue(base_data,8) == 0): continue
        #print chr(getValue(base_data,4)&0xFF)
        c = chr(getValue(base_data,4)&0xFF)
        sys.stdout.write(c)
        sys.stdout.flush()
        setValue(base_data, 4, 0)
        setValue(base_data, 8, 0)
        """
        #AFTER_EXECUTION.bin should continue binary until first print for setup to have happened
        f = open("AFTER_EXECUTION.bin", "wb")
        f.write(''.join(base_data))
        f.close()
        break
        """
        #0x2DAD
offset = 0x223
vmCode(list(binary), 0x2DAD, 5)
print "Done.."