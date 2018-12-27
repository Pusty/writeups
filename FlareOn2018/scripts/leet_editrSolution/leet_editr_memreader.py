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

dataDump = ""

sc = text_section.addr + (0x10F11CC-0x10F1000)

pluginsdk.SetBreakpoint(sc)
pluginsdk.Run()
pluginsdk.Wait()
pluginsdk.Run()
pluginsdk.Wait()


pluginsdk.WriteByte(sc, 0x8B)
pluginsdk.WriteByte(sc+1, 0x48)
pluginsdk.WriteByte(sc+2, 0x18)
pluginsdk.WriteByte(sc+3, 0x8A)
pluginsdk.WriteByte(sc+4, 0x01)
pluginsdk.WriteByte(sc+5, 0x41)
pluginsdk.WriteByte(sc+6, 0xEB)
pluginsdk.WriteByte(sc+7, 0xFB)

pluginsdk.x64dbg.DbgCmdExec('deleteBPX')

"""
003311CC | 8B 48 18                 | mov ecx,dword ptr ds:[eax+18]           |
003311CF | 8A 01                    | mov al,byte ptr ds:[ecx]                |
003311D1 | 41                       | inc ecx                                 |
003311D2 | EB FB                    | jmp leet_editr.3311CF                   |
"""
#this code assumes that shellcode is already setup


for i in range(0x10000):
    pluginsdk.Run()
    pluginsdk.Wait()
    #read exception
    dataDump += chr(pluginsdk.GetEAX()&0xFF)
    pluginsdk.Run()
    pluginsdk.Wait()


print("Done...")
f1 = open("dataDump.bin", "wb")
f1.write(dataDump)
f1.close()