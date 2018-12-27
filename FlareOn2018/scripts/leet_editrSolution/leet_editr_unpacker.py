import struct
from ctypes import *
from x64dbgpy import *



def get_section(section_name, module=pluginsdk.GetMainModuleInfo()):
    for i in xrange(module.sectionCount):
        section = pluginsdk.SectionFromAddr(module.base, i)
        if section.name == section_name:
            return section
            

def disasm_at(addr):
    inst = pluginsdk.x64dbg.DISASM_INSTR()
    res = pluginsdk.x64dbg.DbgDisasmAt(addr, inst)
    return inst

print("======================>")
text_section = get_section(".text")
print text_section.addr
pluginsdk.SetBreakpoint(text_section.addr + (0x10F11CC-0x10F1000))
pluginsdk.SetBreakpoint(text_section.addr + (0x10F1721-0x10F1000))
pluginsdk.SetBreakpoint(text_section.addr + (0x03B1683-0x03B1000))
pluginsdk.Run()
pluginsdk.Wait()
pluginsdk.Run()
pluginsdk.Wait()

contentInst = ""
contentByte = ""
offset      = 0x14 # run this with offset = -1, 0, 8, 0xC, 0x10, 0x14

struct = pluginsdk.ReadDword(pluginsdk.GetESP())
print hex(struct)
newEsi = pluginsdk.ReadDword(struct+offset)
print hex(newEsi)
if offset != -1:
    pluginsdk.SetESI(newEsi)
pluginsdk.Run()


for i in range(0x500):
    pluginsdk.Wait()
    curAddr = pluginsdk.GetEIP()
    print hex(curAddr)
    pluginsdk.Run()
    pluginsdk.Wait()
    curInst = disasm_at(curAddr)
    curLen  = curInst.instr_size
    print hex(pluginsdk.GetEIP())
    print curInst.instruction
    contentInst += curInst.instruction
    contentInst += "\n"
    for i in range(curLen):
        contentByte += chr(pluginsdk.ReadByte(curAddr+i))
    #if 'ret' in curInst.instruction:
    #    break
    #for i in range(curLen):
    #    pluginsdk.WriteByte(curAddr+i, 0x90)
    #https://stackoverflow.com/questions/25545470/long-multi-byte-nops-commonly-understood-macros-or-other-notation
    if curLen == 1:
        pluginsdk.WriteByte(curAddr,   0x90)
    elif curLen == 2:
        pluginsdk.WriteByte(curAddr,   0x66)
        pluginsdk.WriteByte(curAddr+1, 0x90)
    elif curLen == 3:
        pluginsdk.WriteByte(curAddr,   0x0f)
        pluginsdk.WriteByte(curAddr+1, 0x1f)
        pluginsdk.WriteByte(curAddr+2, 0x00)
    elif curLen == 4:
        pluginsdk.WriteByte(curAddr,   0x0f)
        pluginsdk.WriteByte(curAddr+1, 0x1f)
        pluginsdk.WriteByte(curAddr+2, 0x40)
        pluginsdk.WriteByte(curAddr+3, 0x00)
    elif curLen == 5:
        pluginsdk.WriteByte(curAddr,   0x0f)
        pluginsdk.WriteByte(curAddr+1, 0x1f)
        pluginsdk.WriteByte(curAddr+2, 0x44)
        pluginsdk.WriteByte(curAddr+3, 0x00)
        pluginsdk.WriteByte(curAddr+4, 0x00)
    elif curLen == 6:
        pluginsdk.WriteByte(curAddr,   0x66)
        pluginsdk.WriteByte(curAddr+1, 0x0f)
        pluginsdk.WriteByte(curAddr+2, 0x1f)
        pluginsdk.WriteByte(curAddr+3, 0x44)
        pluginsdk.WriteByte(curAddr+4, 0x00)
        pluginsdk.WriteByte(curAddr+5, 0x00)
    elif curLen == 7:
        pluginsdk.WriteByte(curAddr,   0x0f)
        pluginsdk.WriteByte(curAddr+1, 0x1f)
        pluginsdk.WriteByte(curAddr+2, 0x80)
        pluginsdk.WriteByte(curAddr+3, 0x00)
        pluginsdk.WriteByte(curAddr+4, 0x00)
        pluginsdk.WriteByte(curAddr+5, 0x00)
        pluginsdk.WriteByte(curAddr+6, 0x00)
    elif curLen == 8:
        pluginsdk.WriteByte(curAddr,   0x0f)
        pluginsdk.WriteByte(curAddr+1, 0x1f)
        pluginsdk.WriteByte(curAddr+2, 0x84)
        pluginsdk.WriteByte(curAddr+3, 0x00)
        pluginsdk.WriteByte(curAddr+4, 0x00)
        pluginsdk.WriteByte(curAddr+5, 0x00)
        pluginsdk.WriteByte(curAddr+6, 0x00)
        pluginsdk.WriteByte(curAddr+7, 0x00)
    elif curLen == 9:
        pluginsdk.WriteByte(curAddr,   0x66)
        pluginsdk.WriteByte(curAddr+1, 0x0f)
        pluginsdk.WriteByte(curAddr+2, 0x1f)
        pluginsdk.WriteByte(curAddr+3, 0x84)
        pluginsdk.WriteByte(curAddr+4, 0x00)
        pluginsdk.WriteByte(curAddr+5, 0x00)
        pluginsdk.WriteByte(curAddr+6, 0x00)
        pluginsdk.WriteByte(curAddr+7, 0x00)
        pluginsdk.WriteByte(curAddr+8, 0x00)
    pluginsdk.Run()
    pluginsdk.Wait()
    print "Skip invalid read"
    pluginsdk.Run()


print("Done...")
f1 = open("contentInst"+hex(offset)+".txt", "w")
f1.write(contentInst)
f1.close()
f1 = open("contentByte"+hex(offset)+".bin", "wb")
f1.write(contentByte)
f1.close()

#change entry: get_section(".text").addr + (0x10F11CC-0x10F1000)
#read decrypt: get_section(".text").addr + (0x10F1721-0x10F1000)
#read decrypt: get_section(".text").addr + (0x10F172C-0x10F1000)


#Adresse=010F1000 that's the offset to .text
#010F11CC here I could change the entry address (esi)

#010F1721 here instructions are decrypted and about to be executed, if possible save them, nop them
#010F172C