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
    
def replaceCode(addr, fileName):
    f = open(fileName, "rb")
    data = f.read()
    f.close()
    for a in range(3):
        for i in range(len(data)/0x1000+1):
            pluginsdk.x64dbg.DbgCmdExec('setpagerights '+hex(addr+0x1000*i)+',"ExecuteReadWrite"')
    for i in range(len(data)):
        pluginsdk.WriteByte(addr+i,ord(data[i]))
    pluginsdk.WriteByte(addr+len(data),0x0)
    pluginsdk.WriteByte(addr+len(data)+1,0x0)

print("======================>")
text_section = get_section(".text")
print text_section.addr
pluginsdk.SetBreakpoint(text_section.addr + (0x10F11CC-0x10F1000))
pluginsdk.Run()
pluginsdk.Wait()
pluginsdk.Run()
pluginsdk.Wait()

pluginsdk.x64dbg.DbgCmdExec('deleteBPX')

struct = pluginsdk.ReadDword(pluginsdk.GetESP())
print hex(struct)

replaceCode(pluginsdk.GetESI(),"contentByte-0x1.bin")
replaceCode(pluginsdk.ReadDword(struct+0x0),"contentByte0x0.bin")
replaceCode(pluginsdk.ReadDword(struct+0x8),"contentByte0x8.bin")
replaceCode(pluginsdk.ReadDword(struct+0xC),"contentByte0xC.bin")
replaceCode(pluginsdk.ReadDword(struct+0x10),"contentByte0x10.bin")
replaceCode(pluginsdk.ReadDword(struct+0x14),"contentByte0x14.bin")
replaceCode(pluginsdk.ReadDword(struct+0x18),"dataDump.bin")

print("Done...")