import struct
import traceback
import os
import math

from binaryninja import *
from types import *

from .vmquackdis import *
from .vmquacklift import InstructionIL 
            

def decode_instruction(data, addr):
        if len(data) < 5:
            return None, None, None
            
        inst, size, match = tryToParse(data) # in vmquackdis
        
        if inst == None:
            return None, None, None
            
        for l in inst[2]:
            if l[0] == TYPE_REG:
                if not match[l[2]] in regnames:
                    return None, None, None
            
        return inst, size, match
        
    
def signOffset(off, size):
    if size == 8:
        off = off & 0xFF
        return off | (-(off & 0x80))
    elif size == 16:
        off = off & 0xFFFF
        return off | (-(off & 0x8000))
    elif size == 24:
        off = off & 0xFFFFFF
        return off | (-(off & 0x800000))
    elif size == 32:
        off = off & 0xFFFFFFFF
        return off | (-(off & 0x80000000))
    return off
        
regnames = {
    0: "zero",
    1: "lr",
    2: "rsp",
    3: "rbp",
    4: "r4",
    5: "r5",
    6: "sarg1",
    7: "sarg2",
    8: "sarg3",
    9: "sarg4",
    10: "sarg5",
    11: "sarg6",
    12: "r12",
    13: "r13",
    14: "r14",
    15: "r15",
    16: "r16",
    17: "r17",
    18: "r18",
    19: "r19",
    20: "r20",
    21: "r21",
    22: "r22",
    23: "r23",
    24: "r24",
    25: "r25",
    26: "r26",
    49: "r49",
    67: "r67",
    69: "r69",
    85: "r85",
    97: "r97",
    104: "r104",
    167: "r167",
    179: "r179",
    181: "r181",
    214: "r214",
    224: "r224",
    226: "r226",
    236: "r236",
    242: "r242",
    248: "r248",
}

def initRegs():
    regs = {}
    for k in regnames:
        nameVar = regnames[k]
        regs[nameVar] = RegisterInfo(nameVar, 8)
    return regs

class VMQuack(Architecture):

    name = 'VMQuack'
    address_size = 8
    default_int_size = 8
    instr_alignment = 1
    max_instr_length = 10
    
    #endianness = Endianness.LittleEndian

    # register related stuff
    
    regs = initRegs()
    
    stack_pointer = "rsp"
    link_reg  = "lr"
    system_regs  = ["r5", "sarg1", "sarg2", "sarg3", "sarg4"]
    
    flags = {}
    flag_roles = {}
    flag_write_types = {}
    flags_written_by_flag_write_type = {}
    flags_required_for_flag_condition = {}
    


    def get_instruction_info(self, data, addr):
    
        inst, size, match = decode_instruction(data, addr)
        
        
        
        if inst == None:
            return None
            
        result = InstructionInfo()
        result.length = size

            

        
        instName = inst[0].split(" ")[0]
        
        JMP_NAMES = ["J.E", "J.NE", "J.AE", "J.B", "J.G", "J.L"] 

        if not ((instName in JMP_NAMES) or instName == "CALL" or instName == "JMP" or instName == "RETURN" or instName == "SYSCALL" or instName == "EXTCALL"):
            return result


        if instName == "JMP" or instName == "RETURN":
            # UNCONDITIONAL JUMP (can be return)
            offset = None
            reg = None
            for l in inst[2]:
                if l[0] == TYPE_PCOFFSET:
                    offset = signOffset(match[l[2]], l[1])*5
                if l[0] == TYPE_REG:
                    reg = regnames[match[l[2]]]
            
            if reg == None and offset != None:
                result.add_branch(BranchType.UnconditionalBranch, addr + size + offset)
            elif reg == "lr" and offset == None:
                result.add_branch(BranchType.FunctionReturn)
            else:
                result.add_branch(BranchType.IndirectBranch)
            

            
        if instName in JMP_NAMES:
            # CONDITIONAL BRANCH
            for l in inst[2]:
                if l[0] == TYPE_PCOFFSET:
                    result.add_branch(BranchType.TrueBranch, addr + size + signOffset(match[l[2]], l[1])*5)
            result.add_branch(BranchType.FalseBranch, addr + size)


        if instName == "CALL":
           # DIRECT CALL
            reg = None
            for l in inst[2]:
                if l[0] == TYPE_PCOFFSET:
                    offset = signOffset(match[l[2]], l[1])*5
                if l[0] == TYPE_REG:
                    reg = regnames[match[l[2]]]
                    
            if reg == None and offset != None:
                result.add_branch(BranchType.CallDestination, addr + size + offset)
            else:
                result.add_branch(BranchType.IndirectBranch)

        if instName == "SYSCALL" or instName == "EXTCALL":
            result.add_branch(BranchType.SystemCall)    
            
            
           
        return result

        

        
    def get_instruction_text(self, data, addr):
    
        inst, size, match = decode_instruction(data, addr)
        
        if inst == None:
            return None
            
        result = []

        instName = inst[0].split(" ")[0]
        
        if instName == "JMP" and (inst[2][0][0] == TYPE_REG and regnames[match[inst[2][0][2]]] == "lr") and (inst[2][1][0] == TYPE_IMM and match[inst[2][1][2]] == 0):
            result.append(InstructionTextToken( InstructionTextTokenType.InstructionToken, "RETURN"))
            return result, size
        
        result.append(InstructionTextToken( InstructionTextTokenType.InstructionToken, instName))
        

        regStr = ""
        parIndex = 0
        for l in inst[2]:
            if parIndex > 0:
                result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ','))
            result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
            
            if l[0] == TYPE_IMM:
                num = match[l[2]]
                v = signOffset(num, l[1])
                if v < 0:
                    num = v
                    numStr = str(v)
                else:
                    numStr = hex(v)
                    
                result.append(InstructionTextToken(InstructionTextTokenType.TextToken, '#'))
                result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, numStr, num))
            elif l[0] == TYPE_REG:
                reg = match[l[2]]
                regStr = regnames[reg]
                result.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, regStr))
            elif l[0] == TYPE_PCOFFSET:
                pcOffset = signOffset(match[l[2]], l[1])*5
                result.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(addr+pcOffset+size), addr+pcOffset+size))
            parIndex = parIndex + 1
        
        return result, size

    
    def get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
        return Architecture.get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)
        
        

    def get_instruction_low_level_il(self, data, addr, il):
        inst, size, match = decode_instruction(data, addr)
        if inst == None: return None

        instName = inst[0].split(" ")[0]
        
        args = []
        
        for l in inst[2]:
            if l[0] == TYPE_IMM:
                args.append((TYPE_IMM, math.ceil(l[1]/8), signOffset(match[l[2]], l[1]), addr+size))
            elif l[0] == TYPE_REG:
                args.append((TYPE_REG, math.ceil(l[1]/8), regnames[match[l[2]]]))
            elif l[0] == TYPE_PCOFFSET:
                args.append((TYPE_PCOFFSET, math.ceil(l[1]/8), addr+signOffset(match[l[2]], l[1])*5+size, addr+size, match[l[2]]))
        
        if InstructionIL.get(instName) is not None:
            instLifted = InstructionIL[instName](il, args)
            if isinstance(instLifted, list):
                for i in instLifted:
                    if isinstance(i, LambdaType):
                        i(il, args)
                    else:    
                        il.append(i)
            elif instLifted is not None:
                il.append(instLifted)
        else:
            il.append(il.unimplemented())
        

        return size

        
VMQuack.register()

class VMQuackCallingConvention(CallingConvention):
    name = "VMQuackCC"
    caller_saved_regs = ["lr", "rbp", "r13"]
    int_arg_regs = ["r5", "sarg1", "sarg2", "sarg3", "sarg4", "sarg5", "sarg6"] #["r5", "arg1", "arg2", "arg3", "arg4", "arg5", "arg6"]
    int_return_reg = "r5"
    high_int_return_reg = "sarg1"


Architecture['VMQuack'].register_calling_convention(VMQuackCallingConvention(Architecture['VMQuack'], "default"))
Architecture['VMQuack'].standalone_platform.default_calling_convention = Architecture['VMQuack'].calling_conventions['default']


from binaryninja.binaryview import BinaryView


class VMQuackView(BinaryView):
    name = "VMQuack"
    long_name = "VMQuack Binary View"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture['VMQuack'].standalone_platform

    @staticmethod
    def is_valid_for_data(data):
        hdr = data.read(0, 6)
        if len(hdr) < 6:
            return False
        if hdr[:4] != b"\x10\x70\x33\x01":
            return False
        return True

    def init(self):
        self.binary_length=0x7000
        self.add_auto_segment(0, self.binary_length, 0, self.binary_length, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0xFF00000000000, 0x2000, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_user_section(".code", 0, self.binary_length, SectionSemantics.ReadOnlyCodeSectionSemantics  )

        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0, "start"))
        self.add_entry_point(0x45c)
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0x45c
        
VMQuackView.register()
