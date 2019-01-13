"""
    This a very minimalistic DLX implementation meant for testing and executing its assembly.
    I'm no trying to be follow any existing Opcode/Function standart as there are a few and all basically abitrary.
    My implementation doesn't try to emulate the Pipelining and internal states either.

    As a debugging messuremeant I both provide the "not real" instructions HALT and DEBUG #immediate as well
        HALT      - Stop the program immediatly
        DEBUG imm - Used as breakpoints, immediate value used for identification
                    
    Jumping to address 0xFFFF exits the program as well
    Trap will continue execution at the address contained at TrapValue*4
    Code,Data and Memory shares the same place in my implementation and is both fully readable and writeable and also zeroed out by default
    Floating Point Instructions work but are not formally correctly implemented, expecially notable for working with double values and me not implementing their affect on multiple floating point registers
    
    Code execution starts at address 0x8000
"""

import struct
import copy 

from DLXinst import *
from DLXasm  import *


CODE_START = 0x8000


class IntegerRegister:
    values = [0]*32
    def __setitem__(self, key, data):
        if key == 0: return # can't write to register 0
        self.values[key] = U(data)
    def __getitem__(self, key):
        return E(self.values[key],32)
    
class FloatRegister:
    values = [0.0]*32
    def __setitem__(self, key, data):
        self.values[key] = data
    def __getitem__(self, key):
        return self.values[key]

class RegisterContext:
    PC      = 0
    R       = IntegerRegister()
    F       = FloatRegister()
    FPSR    = 0
    Special = 0
    safeState = None # contains deep copy of saved register state

class EmulatorContext:
    debug = False  # Whether Debug mode is enabled
    stopped = False
    regs = RegisterContext()
    memory = bytearray("\x00"*0xFFFF)
    
    debugText   = "" #debug source code
    debugLineNr = "" #debug information for code optinally containing lineNrs
    
    def writeBytes(self,index, data):
        for i in range(len(data)):
            self.memory[index+i] = data[i]
            
    def writeDouble(self,index, flo):
        self.writeBytes(index, struct.pack("<d",flo))
            
    def writeFloat(self,index, flo):
        self.writeBytes(index, struct.pack("<f",flo))
            
    def writeWord(self,index, integer):
        self.writeBytes(index, struct.pack("<I",integer&0xFFFFFFFF))
        
    def writeHalfWord(self,index, integer):
        self.writeBytes(index, struct.pack("<H",integer&0xFFFF))
        
    def writeByte(self,index, integer):
        self.writeBytes(index, struct.pack("<B",integer&0xFF))
        
    def readDouble(self,index):
        return struct.unpack("<d",self.memory[index:index+8])[0]
            
    def readFloat(self,index):
        return struct.unpack("<f",self.memory[index:index+4])[0]
            
    def readWord(self,index):
        return struct.unpack("<I",self.memory[index:index+4])[0]
        
    def readSignedWord(self,index):
        return struct.unpack("<i",self.memory[index:index+4])[0]
        
    def readHalfWord(self,index):
        return struct.unpack("<H",self.memory[index:index+2])[0]
        
    def readSignedHalfWord(self,index):
        return struct.unpack("<h",self.memory[index:index+2])[0]
        
    def readByte(self,index):
        return struct.unpack("<B",self.memory[index:index+1])[0]
        
    def readSignedByte(self,index):
        return struct.unpack("<b",self.memory[index:index+1])[0]
    
def E(value, size, signed=False):
    v = 0
    if size == 32: #biggest sign extend size 32bit
        v = ((value&0x7fffffff) - (value&0x80000000))
    if size == 26: #sign extend size 26bit
        v = ((value&0x1ffffff) - (value&0x2000000))
    elif size == 16: #sign extend 16bit
        v = ((value&0x7fff) - (value&0x8000))
    elif size == 8: #sign extend 8bit
        v = ((value&0x7f)-(value&0x80))
    if not signed: #extend to 32bit
        v = v & 0xFFFFFFFF
    return v
    
def U(v):
    return v&0xFFFFFFFF
    
def emulate(context):
    if context.stopped:
        return False

    instValue = struct.unpack("<I",context.memory[context.regs.PC:context.regs.PC+4])[0]
    
    if (instValue&0x3f, 0) in InstructionsOF and InstructionsOF[(instValue&0x3f, 0)].encodingScheme != ENCODING_R:
        #Normal Opcodes
        opvalue = instValue&0x3f
        function = 0
        inst = InstructionsOF[(opvalue, 0)]
        if inst.encodingScheme == ENCODING_I:
            Xs   = (instValue>>6)&0x1f
            Xd   = (instValue>>11)&0x1f
            imm  = (instValue>>16)&0xFFFF
            immE = E(imm, 16, signed=True)
            dest = E(imm, 16, signed=True)
            addr = context.regs.R[Xs]+immE
        elif inst.encodingScheme == ENCODING_J:
            imm  = E((instValue>>6)&0x3ffffff, 26, signed=False)
            dest = E((instValue>>6)&0x3ffffff, 26, signed=True) # sign this
        else:
            raise ValueError("Invalid Encoding for opcode '"+hex(opvalue)+"'")
            return
    elif (instValue&0x3f,(instValue>>21)&0x3ff) in InstructionsOF and InstructionsOF[(instValue&0x3f, (instValue>>21)&0x3ff)].encodingScheme == ENCODING_R:
        # R-type Special Opcodes
        opvalue = instValue&0x3f
        function = (instValue>>21)&0x3ff
        inst = InstructionsOF[(opvalue, function)]
        Xs   = (instValue>>6)&0x1f
        Xc   = (instValue>>11)&0x1f
        Xd   = (instValue>>16)&0x1f
    else:
        raise ValueError("Not a valid instruction at address "+hex(context.regs.PC))
        return
    
    if((context.regs.PC - CODE_START) < len(context.debugLineNr)):
        f = context.regs.PC - CODE_START
        lineNr = struct.unpack("<I",context.debugLineNr[f:f+4])[0]
        if lineNr < len(context.debugText):
            print(("%04X"%context.regs.PC)+": "+context.debugText[lineNr].split(";")[0].strip())
    
    #opcode list for "special" R-type instructions
    if inst.opcode == Instructions["SLL"].opcode and inst.functionValue == Instructions["SLL"].functionValue:
         context.regs.R[Xd] = context.regs.R[Xs] << (context.regs.R[Xc]&0x1f)
    elif inst.opcode == Instructions["SRL"].opcode and inst.functionValue == Instructions["SRL"].functionValue:
         context.regs.R[Xd] = U(context.regs.R[Xs]) >> (context.regs.R[Xc]&0x1f)
    elif inst.opcode == Instructions["SRA"].opcode and inst.functionValue == Instructions["SRA"].functionValue:
         context.regs.R[Xd] = E(context.regs.R[Xs]) >> (context.regs.R[Xc]&0x1f)
    elif inst.opcode == Instructions["ADD"].opcode and inst.functionValue == Instructions["ADD"].functionValue:
         context.regs.R[Xd] = context.regs.R[Xs] + context.regs.R[Xc]
    elif inst.opcode == Instructions["ADDU"].opcode and inst.functionValue == Instructions["ADDU"].functionValue:
         context.regs.R[Xd] = U(context.regs.R[Xs]) + U(context.regs.R[Xc])
    elif inst.opcode == Instructions["SUB"].opcode and inst.functionValue == Instructions["SUB"].functionValue:
         context.regs.R[Xd] = context.regs.R[Xs] - context.regs.R[Xc]
    elif inst.opcode == Instructions["SUBU"].opcode and inst.functionValue == Instructions["SUBU"].functionValue:
         context.regs.R[Xd] = U(context.regs.R[Xs]) - U(context.regs.R[Xc])
    elif inst.opcode == Instructions["AND"].opcode and inst.functionValue == Instructions["AND"].functionValue:
         context.regs.R[Xd] = U(context.regs.R[Xs]) & U(context.regs.R[Xc])
    elif inst.opcode == Instructions["OR"].opcode and inst.functionValue == Instructions["OR"].functionValue:
         context.regs.R[Xd] = U(context.regs.R[Xs]) | U(context.regs.R[Xc])
    elif inst.opcode == Instructions["XOR"].opcode and inst.functionValue == Instructions["XOR"].functionValue:
         context.regs.R[Xd] = U(context.regs.R[Xs]) ^ U(context.regs.R[Xc])
    elif inst.opcode == Instructions["SEQ"].opcode and inst.functionValue == Instructions["SEQ"].functionValue:
         context.regs.R[Xd] = 1 if context.regs.R[Xs] == context.regs.R[Xc] else 0
    elif inst.opcode == Instructions["SNE"].opcode and inst.functionValue == Instructions["SNE"].functionValue:
         context.regs.R[Xd] = 1 if context.regs.R[Xs] != context.regs.R[Xc] else 0
    elif inst.opcode == Instructions["SLT"].opcode and inst.functionValue == Instructions["SLT"].functionValue:
         context.regs.R[Xd] = 1 if context.regs.R[Xs] < context.regs.R[Xc] else 0
    elif inst.opcode == Instructions["SGT"].opcode and inst.functionValue == Instructions["SGT"].functionValue:
         context.regs.R[Xd] = 1 if context.regs.R[Xs] > context.regs.R[Xc] else 0
    elif inst.opcode == Instructions["SLE"].opcode and inst.functionValue == Instructions["SLE"].functionValue:
         context.regs.R[Xd] = 1 if context.regs.R[Xs] <= context.regs.R[Xc] else 0
    elif inst.opcode == Instructions["SGE"].opcode and inst.functionValue == Instructions["SGE"].functionValue:
         context.regs.R[Xd] = 1 if context.regs.R[Xs] >= context.regs.R[Xc] else 0
    elif inst.opcode == Instructions["MOVI2S"].opcode and inst.functionValue == Instructions["MOVI2S"].functionValue:
         context.regs.Special = context.regs.R[Xs]
    elif inst.opcode == Instructions["MOVS2I"].opcode and inst.functionValue == Instructions["MOVS2I"].functionValue:
         context.regs.R[Xd] = context.regs.Special
         
    # Floating Point Instructions Here
    
    elif inst.opcode == Instructions["ADDF"].opcode and inst.functionValue == Instructions["ADDF"].functionValue:
         context.regs.F[Xd] = context.regs.F[Xs] + context.regs.F[Xc]
    elif inst.opcode == Instructions["SUBF"].opcode and inst.functionValue == Instructions["SUBF"].functionValue:
         context.regs.F[Xd] = context.regs.F[Xs] - context.regs.F[Xc]
    elif inst.opcode == Instructions["MULTF"].opcode and inst.functionValue == Instructions["MULTF"].functionValue:
         context.regs.F[Xd] = context.regs.F[Xs] * context.regs.F[Xc]
    elif inst.opcode == Instructions["DIVF"].opcode and inst.functionValue == Instructions["DIVF"].functionValue:
         context.regs.F[Xd] = context.regs.F[Xs] / context.regs.F[Xc]
    elif inst.opcode == Instructions["ADDD"].opcode and inst.functionValue == Instructions["ADDD"].functionValue:
         context.regs.F[Xd] = context.regs.F[Xs] + context.regs.F[Xc]
         context.regs.F[Xd+1] = 0
    elif inst.opcode == Instructions["SUBD"].opcode and inst.functionValue == Instructions["SUBD"].functionValue:
         context.regs.F[Xd] = context.regs.F[Xs] - context.regs.F[Xc]
         context.regs.F[Xd+1] = 0
    elif inst.opcode == Instructions["MULTD"].opcode and inst.functionValue == Instructions["MULTD"].functionValue:
         context.regs.F[Xd] = context.regs.F[Xs] * context.regs.F[Xc]
         context.regs.F[Xd+1] = 0
    elif inst.opcode == Instructions["DIVD"].opcode and inst.functionValue == Instructions["DIVD"].functionValue:
         context.regs.F[Xd] = context.regs.F[Xs] / context.regs.F[Xc]
         context.regs.F[Xd+1] = 0
    elif inst.opcode == Instructions["CVTF2D"].opcode and inst.functionValue == Instructions["CVTF2D"].functionValue:
         context.regs.F[Xd] = context.regs.F[Xs]
         context.regs.F[Xd+1] = 0
    elif inst.opcode == Instructions["CVTF2I"].opcode and inst.functionValue == Instructions["CVTF2I"].functionValue:
         context.regs.R[Xd] = int(context.regs.F[Xs])
    elif inst.opcode == Instructions["CVTD2F"].opcode and inst.functionValue == Instructions["CVTD2F"].functionValue:
         context.regs.F[Xd] = context.regs.F[Xs]
    elif inst.opcode == Instructions["CVTD2I"].opcode and inst.functionValue == Instructions["CVTD2I"].functionValue:
         context.regs.R[Xd] = int(context.regs.F[Xs])
    elif inst.opcode == Instructions["CVTI2F"].opcode and inst.functionValue == Instructions["CVTI2F"].functionValue:
         context.regs.F[Xd] = float(context.regs.R[Xs])
    elif inst.opcode == Instructions["CVTI2D"].opcode and inst.functionValue == Instructions["CVTI2D"].functionValue:
         context.regs.F[Xd] = float(context.regs.R[Xs])
         context.regs.F[Xd+1] = 0
    elif inst.opcode == Instructions["MULT"].opcode and inst.functionValue == Instructions["MULT"].functionValue:
         context.regs.R[Xd] = context.regs.R[Xs] * context.regs.R[Xc]
    elif inst.opcode == Instructions["DIV"].opcode and inst.functionValue == Instructions["DIV"].functionValue:
         context.regs.R[Xd] = context.regs.R[Xs] / context.regs.R[Xc]
    elif inst.opcode == Instructions["EQF"].opcode and inst.functionValue == Instructions["EQF"].functionValue:
         context.regs.FPSR = 1 if context.regs.F[Xs] == context.regs.F[Xc] else 0
    elif inst.opcode == Instructions["NEF"].opcode and inst.functionValue == Instructions["NEF"].functionValue:
         context.regs.FPSR = 1 if context.regs.F[Xs] != context.regs.F[Xc] else 0
    elif inst.opcode == Instructions["LTF"].opcode and inst.functionValue == Instructions["LTF"].functionValue:
         context.regs.FPSR = 1 if context.regs.F[Xs] < context.regs.F[Xc] else 0
    elif inst.opcode == Instructions["GTF"].opcode and inst.functionValue == Instructions["GTF"].functionValue:
         context.regs.FPSR = 1 if context.regs.F[Xs] > context.regs.F[Xc] else 0
    elif inst.opcode == Instructions["LEF"].opcode and inst.functionValue == Instructions["LEF"].functionValue:
         context.regs.FPSR = 1 if context.regs.F[Xs] <= context.regs.F[Xc] else 0
    elif inst.opcode == Instructions["GEF"].opcode and inst.functionValue == Instructions["GEF"].functionValue:
         context.regs.FPSR = 1 if context.regs.F[Xs] >= context.regs.F[Xc] else 0
    elif inst.opcode == Instructions["MULTU"].opcode and inst.functionValue == Instructions["MULTU"].functionValue:
         context.regs.R[Xd] = U(context.regs.R[Xs]) * U(context.regs.R[Xc])
    elif inst.opcode == Instructions["DIVU"].opcode and inst.functionValue == Instructions["DIVU"].functionValue:
         context.regs.R[Xd] = U(context.regs.R[Xs]) / U(context.regs.R[Xc])
    elif inst.opcode == Instructions["EQD"].opcode and inst.functionValue == Instructions["EQD"].functionValue:
         context.regs.FPSR = 1 if context.regs.F[Xs] == context.regs.F[Xc] else 0
    elif inst.opcode == Instructions["NED"].opcode and inst.functionValue == Instructions["NED"].functionValue:
         context.regs.FPSR = 1 if context.regs.F[Xs] != context.regs.F[Xc] else 0
    elif inst.opcode == Instructions["LTD"].opcode and inst.functionValue == Instructions["LTD"].functionValue:
         context.regs.FPSR = 1 if context.regs.F[Xs] < context.regs.F[Xc] else 0
    elif inst.opcode == Instructions["GTD"].opcode and inst.functionValue == Instructions["GTD"].functionValue:
         context.regs.FPSR = 1 if context.regs.F[Xs] > context.regs.F[Xc] else 0
    elif inst.opcode == Instructions["LED"].opcode and inst.functionValue == Instructions["LED"].functionValue:
         context.regs.FPSR = 1 if context.regs.F[Xs] <= context.regs.F[Xc] else 0
    elif inst.opcode == Instructions["GED"].opcode and inst.functionValue == Instructions["GED"].functionValue:
         context.regs.FPSR = 1 if context.regs.F[Xs] >= context.regs.F[Xc] else 0
    
    # Normal I/J-Type Instructions
    
    elif inst.opcode == Instructions["J"].opcode and inst.functionValue == Instructions["J"].functionValue:
        context.regs.PC += dest
        context.regs.PC -= 4
    elif inst.opcode == Instructions["JAL"].opcode and inst.functionValue == Instructions["JAL"].functionValue:
        context.regs.R[31] = context.regs.PC + 4
        context.regs.PC += dest
        context.regs.PC -= 4
    elif inst.opcode == Instructions["BEQZ"].opcode and inst.functionValue == Instructions["BEQZ"].functionValue:
        if(context.regs.R[Xs] == 0):
            context.regs.PC += dest
            context.regs.PC -= 4
    elif inst.opcode == Instructions["BNEZ"].opcode and inst.functionValue == Instructions["BNEZ"].functionValue:
        if(context.regs.R[Xs] != 0):
            context.regs.PC += dest
            context.regs.PC -= 4
    elif inst.opcode == Instructions["BFPT"].opcode and inst.functionValue == Instructions["BFPT"].functionValue:
        if(context.regs.FPSR == 0):
            context.regs.PC += dest
            context.regs.PC -= 4
    elif inst.opcode == Instructions["BFPF"].opcode and inst.functionValue == Instructions["BFPF"].functionValue:
        if(context.regs.FPSR != 0):
            context.regs.PC += dest
            context.regs.PC -= 4
    elif inst.opcode == Instructions["ADDI"].opcode and inst.functionValue == Instructions["ADDI"].functionValue:
        context.regs.R[Xd] = context.regs.R[Xs] + immE
    elif inst.opcode == Instructions["ADDUI"].opcode and inst.functionValue == Instructions["ADDUI"].functionValue:
        context.regs.R[Xd] = U(context.regs.R[Xs]) + imm
    elif inst.opcode == Instructions["SUBI"].opcode and inst.functionValue == Instructions["SUBI"].functionValue:
        context.regs.R[Xd] = context.regs.R[Xs] - immE
    elif inst.opcode == Instructions["SUBUI"].opcode and inst.functionValue == Instructions["SUBUI"].functionValue:
        context.regs.R[Xd] = U(context.regs.R[Xs]) - imm
    elif inst.opcode == Instructions["ANDI"].opcode and inst.functionValue == Instructions["ANDI"].functionValue:
        context.regs.R[Xd] = U(context.regs.R[Xs]) & imm
    elif inst.opcode == Instructions["ORI"].opcode and inst.functionValue == Instructions["ORI"].functionValue:
        context.regs.R[Xd] = U(context.regs.R[Xs]) | imm
    elif inst.opcode == Instructions["XORI"].opcode and inst.functionValue == Instructions["XORI"].functionValue:
        context.regs.R[Xd] = U(context.regs.R[Xs]) ^ imm
    elif inst.opcode == Instructions["LHI"].opcode and inst.functionValue == Instructions["LHI"].functionValue:
        context.regs.R[Xd] = immE << 16
    elif inst.opcode == Instructions["RFE"].opcode and inst.functionValue == Instructions["RFE"].functionValue:
        context.regs = context.regs.safeState
    elif inst.opcode == Instructions["TRAP"].opcode and inst.functionValue == Instructions["TRAP"].functionValue:
        context.regs.safeState = copy.deepcopy(context.regs)
        context.regs.PC = struct.unpack("<I",context.memory[imm*4:imm*4+4])[0]
    elif inst.opcode == Instructions["JR"].opcode and inst.functionValue == Instructions["JR"].functionValue:
        context.regs.PC = U(context.regs.R[Xs])
        context.regs.PC -= 4
    elif inst.opcode == Instructions["JALR"].opcode and inst.functionValue == Instructions["JALR"].functionValue:
        context.regs.R[31] = context.regs.PC + 4
        context.regs.PC = U(context.regs.R[Xs])
        context.regs.PC -= 4
    elif inst.opcode == Instructions["SLLI"].opcode and inst.functionValue == Instructions["SLLI"].functionValue:
        context.regs.R[Xd] = context.regs.R[Xs] << (imm&0x1f)
    elif inst.opcode == Instructions["SRLI"].opcode and inst.functionValue == Instructions["SRLI"].functionValue:
        context.regs.R[Xd] = U(context.regs.R[Xs]) >> (imm&0x1f)
    elif inst.opcode == Instructions["SRAI"].opcode and inst.functionValue == Instructions["SRAI"].functionValue:
        context.regs.R[Xd] = E(context.regs.R[Xs]) >> (imm&0x1f)
    elif inst.opcode == Instructions["SEQI"].opcode and inst.functionValue == Instructions["SEQI"].functionValue:
        context.regs.R[Xd] = 1 if context.regs.R[Xs] == immE else 0
    elif inst.opcode == Instructions["SNEI"].opcode and inst.functionValue == Instructions["SNEI"].functionValue:
        context.regs.R[Xd] = 1 if context.regs.R[Xs] != immE else 0
    elif inst.opcode == Instructions["SLTI"].opcode and inst.functionValue == Instructions["SLTI"].functionValue:
        context.regs.R[Xd] = 1 if context.regs.R[Xs] < immE else 0
    elif inst.opcode == Instructions["SGTI"].opcode and inst.functionValue == Instructions["SGTI"].functionValue:
        context.regs.R[Xd] = 1 if context.regs.R[Xs] > immE else 0
    elif inst.opcode == Instructions["SLEI"].opcode and inst.functionValue == Instructions["SLEI"].functionValue:
        context.regs.R[Xd] = 1 if context.regs.R[Xs] <= immE else 0
    elif inst.opcode == Instructions["SGEI"].opcode and inst.functionValue == Instructions["SGEI"].functionValue:
        context.regs.R[Xd] = 1 if context.regs.R[Xs] >= immE else 0
    elif inst.opcode == Instructions["LB"].opcode and inst.functionValue == Instructions["LB"].functionValue:
        context.regs.R[Xd] = struct.unpack("<b",context.memory[addr:addr+1])[0]
    elif inst.opcode == Instructions["LH"].opcode and inst.functionValue == Instructions["LH"].functionValue:
        context.regs.R[Xd] = struct.unpack("<h",context.memory[addr:addr+2])[0]
    elif inst.opcode == Instructions["LW"].opcode and inst.functionValue == Instructions["LW"].functionValue:
        context.regs.R[Xd] = struct.unpack("<I",context.memory[addr:addr+4])[0]
    elif inst.opcode == Instructions["LBU"].opcode and inst.functionValue == Instructions["LBU"].functionValue:
        context.regs.R[Xd] = struct.unpack("<B",context.memory[addr:addr+1])[0]
    elif inst.opcode == Instructions["LHU"].opcode and inst.functionValue == Instructions["LHU"].functionValue:
        context.regs.R[Xd] = struct.unpack("<H",context.memory[addr:addr+2])[0]
    elif inst.opcode == Instructions["LF"].opcode and inst.functionValue == Instructions["LF"].functionValue:
        context.regs.F[Xd] = struct.unpack("<f",context.memory[addr:addr+4])[0]
    elif inst.opcode == Instructions["LD"].opcode and inst.functionValue == Instructions["LD"].functionValue:
        context.regs.F[Xd] = struct.unpack("<d",context.memory[addr:addr+8])[0]
        context.regs.F[Xd+1] = 0
    elif inst.opcode == Instructions["SB"].opcode and inst.functionValue == Instructions["SB"].functionValue:
        context.writeBytes(addr,struct.pack("<B",context.regs.R[Xd]&0xFF))
    elif inst.opcode == Instructions["SH"].opcode and inst.functionValue == Instructions["SH"].functionValue:
        context.writeBytes(addr,struct.pack("<H",context.regs.R[Xd]&0xFFFF))
    elif inst.opcode == Instructions["SW"].opcode and inst.functionValue == Instructions["SW"].functionValue:
        context.writeBytes(addr,struct.pack("<I",context.regs.R[Xd]&0xFFFFFFFF))
    elif inst.opcode == Instructions["SF"].opcode and inst.functionValue == Instructions["SF"].functionValue:
        context.writeBytes(addr,struct.pack("<f",context.regs.F[Xd]))
    elif inst.opcode == Instructions["SD"].opcode and inst.functionValue == Instructions["SD"].functionValue:
        context.writeBytes(addr,struct.pack("<d",context.regs.F[Xd]))
        
    # Special This Implementation Only Things
    elif inst.opcode == Instructions["HALT"].opcode and inst.functionValue == Instructions["HALT"].functionValue:
        stopped = True;
        return False
    elif inst.opcode == Instructions["DEBUG"].opcode and inst.functionValue == Instructions["DEBUG"].functionValue:
        print("DEBUG: "+str(imm))
        return False
    

    context.regs.PC += 4
    return True


def loadCode(context, code):
    for i,c in enumerate(code):
        context.memory[CODE_START+i] = code[i]
    context.regs.PC = CODE_START
    
def execute(text,emu=None, trace=False, preFunc=None,singleStep=None):
    code,lineNr = parse(text, True)
    
    if emu == None:
        emu = EmulatorContext()
    
    if trace:
        emu.debugLineNr = lineNr
        emu.debugText = text.split("\n")
    
    if preFunc != None:
        preFunc(emu)
    
    loadCode(emu, code)
    
    while emulate(emu):
        if singleStep != None:
            singleStep(emu)

    return emu