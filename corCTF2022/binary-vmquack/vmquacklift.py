from binaryninja import *
from .vmquackdis import *


def R(il, arg):
    if arg[0] == TYPE_IMM:
        return il.const(8, arg[2])
    elif arg[0] == TYPE_REG:
        if(arg[2] == "zero"):
            return il.const(8, 0)
        elif(arg[2] == "r4"):
            return il.const(8, 0xFF00000000000)
        else:
            return il.reg(8, arg[2])
    elif arg[0] == TYPE_PCOFFSET:
        return il.const(8, arg[2])
        

def W(il, arg, value):
    if arg[0] == TYPE_IMM:
        return il.undefined()
    elif arg[0] == TYPE_REG:
        return il.set_reg(8, arg[2], value)
    elif arg[0] == TYPE_PCOFFSET:
        return  il.undefined()
        
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
        
        
def processJump(il, args, call=False):
    dest = None
    offset = None
    reg = None
    for l in args:
        if l[0] == TYPE_PCOFFSET:
            dest = l
        if l[0] == TYPE_IMM:
            offset = (TYPE_IMM, l[1],signOffset(l[2], 16), l[3])
        if l[0] == TYPE_REG:
            reg = l
    
    if not call:
        if reg == None:
            return il.jump(R(il, dest))
        elif reg != None and reg[2] == "lr" and (offset == None or offset[2] == 0):
            return il.ret(R(il, reg))
        else:
            return il.jump(il.add(8, R(il, reg), R(il, offset)))
    else:
        if reg == None:
            return [il.call(il.const_pointer(8, dest[2]))] # , il.set_reg(8, "lr", il.pop(8))
        else:
            return [il.call(il.add(8, R(il, reg), R(il, offset)))]
        #if reg == None:
        #    return [l.set_reg(8, "lr", il.const(8, dest[3])), il.jmp(il.const_pointer(8, dest[2]))]
        #else:
        #    return [il.set_reg(8, "lr", il.const(8, offset[3])), il.jmp(il.add(8, R(il, reg), R(il, offset)))]

def twoRegMul(il, args, op):
    res = op(16, il.sign_extend(16, R(il, args[2])), il.sign_extend(16, R(il, args[3])))
    return [W(il, args[1], il.low_part(8, res)), W(il, args[0], il.low_part(8, il.logical_shift_right(16, res, il.const(16, 64))))]
    
def twoRegDiv(il, args, op, op2):
    res = op(8, R(il, args[2]), R(il, args[3]))
    res2 = op2(8, R(il, args[2]), R(il, args[3]))
    return [W(il, args[1], res), W(il, args[0], res2)]
    
    
def CCJ(il, args, cond):
    offset = args[2]
    if offset[0] != TYPE_PCOFFSET:
        return il.unimplemented()
        
    t = il.get_label_for_address(Architecture['VMQuack'], offset[2])
    f = il.get_label_for_address(Architecture['VMQuack'], offset[3])
    
    if t and f:
        il.append(il.if_expr(cond, t, f))
        return
        
    if t:
        tmp = il.goto(t)
    else:
        tmp = il.jump(il.const_pointer(8, offset[2]))
        
    t = LowLevelILLabel()
    f = LowLevelILLabel()
        
    il.append(il.if_expr(cond, t, f))
    il.mark_label(t)
    il.append(tmp)
    il.mark_label(f)

# maybe wrong?
def LEA(il, args):
    return W(il, args[0], R(il, args[1]))

InstructionIL = {
    "JMP": lambda il, args: processJump(il, args, False),
    "CALL": lambda il, args: processJump(il, args, True),
    "SYSCALL": lambda il, args: il.system_call(),
    "EXTCALL": lambda il, args: il.system_call(),
    "MOV.UPPER": lambda il, args: W(il, args[0], il.shift_left(8, R(il, args[1]), il.const(8, 16))),
    
    "AND": lambda il, args: W(il, args[0], il.and_expr(8, R(il, args[1]), R(il, args[2]))),
    "OR": lambda il, args: W(il, args[0], il.or_expr(8, R(il, args[1]), R(il, args[2]))),
    "XOR": lambda il, args: W(il, args[0], il.xor_expr(8, R(il, args[1]), R(il, args[2]))),
    
    "SHL": lambda il, args: W(il, args[0], il.shift_left(8, R(il, args[1]), R(il, args[2]))),
    "SHR": lambda il, args: W(il, args[0], il.logical_shift_right(8, R(il, args[1]), R(il, args[2]))),
    "SAR": lambda il, args: W(il, args[0], il.arith_shift_right(8, R(il, args[1]), R(il, args[2]))),
    
    "CMP.L": lambda il, args: W(il, args[0], il.compare_signed_less_than(8, R(il, args[1]), R(il, args[2]))),
    "CMP.B": lambda il, args: W(il, args[0], il.compare_unsigned_less_than(8, R(il, args[1]), R(il, args[2]))),
    
    "ADD": lambda il, args: W(il, args[0], il.add(8, R(il, args[1]), R(il, args[2]))),
    "SUB": lambda il, args: W(il, args[0], il.sub(8, R(il, args[1]), R(il, args[2]))),
    "ADD.UPPER": lambda il, args: W(il, args[0], il.add(8, R(il, args[0]), il.shift_left(8, R(il, args[1]), il.const(8, 16)))),
    
    "I.MUL": lambda il, args: twoRegMul(il, args, il.mult),
    "U.MUL": lambda il, args: twoRegMul(il, args, il.mult),
    "I.DIV": lambda il, args: twoRegDiv(il, args, il.div_signed, il.mod_signed),
    "U.DIV": lambda il, args: twoRegDiv(il, args, il.div_unsigned, il.mod_unsigned),
    
    "STR.Q": lambda il, args: il.store(8, il.add(8, R(il, args[1]), R(il, args[2])), R(il, args[0])),
    "STR.D": lambda il, args: il.store(4, il.add(8, R(il, args[1]), R(il, args[2])), il.low_part(4, R(il, args[0]))),
    "STR.W": lambda il, args: il.store(2, il.add(8, R(il, args[1]), R(il, args[2])), il.low_part(2, R(il, args[0]))),
    "STR.B": lambda il, args: il.store(1,  il.add(8, R(il, args[1]), R(il, args[2])), il.low_part(1, R(il, args[0]))),
    
    "LDR.Q": lambda il, args: W(il, args[0], il.load(8, il.add(8, R(il, args[1]), R(il, args[2])))),
    "LDR.D": lambda il, args: W(il, args[0], il.zero_extend(8, il.load(4, il.add(8, R(il, args[1]), R(il, args[2]))))),
    "LDR.W": lambda il, args: W(il, args[0], il.zero_extend(8, il.load(2, il.add(8, R(il, args[1]), R(il, args[2]))))),
    "LDR.B": lambda il, args: W(il, args[0], il.zero_extend(8, il.load(1, il.add(8, R(il, args[1]), R(il, args[2]))))),
    "LDR.SD": lambda il, args: W(il, args[0], il.sign_extend(8, il.load(4, il.add(8, R(il, args[1]), R(il, args[2]))))),
    "LDR.SW": lambda il, args: W(il, args[0], il.sign_extend(8, il.load(2, il.add(8, R(il, args[1]), R(il, args[2]))))),
    "LDR.SB": lambda il, args: W(il, args[0], il.sign_extend(8, il.load(1, il.add(8, R(il, args[1]), R(il, args[2]))))),
    
    "MOV.B": lambda il, args: W(il, args[0], il.zero_extend(8, il.low_part(1, R(il, args[1])))),
    "MOV.W": lambda il, args: W(il, args[0], il.zero_extend(8, il.low_part(2, R(il, args[1])))),
    "MOV.D": lambda il, args: W(il, args[0], il.zero_extend(8, il.low_part(4, R(il, args[1])))),
    "MOV.SB": lambda il, args: W(il, args[0], il.sign_extend(8, il.low_part(1, R(il, args[1])))),
    "MOV.SW": lambda il, args: W(il, args[0], il.sign_extend(8, il.low_part(2, R(il, args[1])))),
    "MOV.SD": lambda il, args: W(il, args[0], il.sign_extend(8, il.low_part(4, R(il, args[1])))),
    
    
    "J.E": lambda il, args: CCJ(il, args, il.compare_equal(8, R(il, args[0]), R(il, args[1]))),
    "J.NE": lambda il, args: CCJ(il, args, il.compare_not_equal(8, R(il, args[0]), R(il, args[1]))),
    "J.L": lambda il, args: CCJ(il, args, il.compare_signed_less_than(8, R(il, args[0]), R(il, args[1]))),
    "J.GE": lambda il, args: CCJ(il, args, il.compare_signed_greater_than(8, R(il, args[0]), R(il, args[1]))),
    "J.B": lambda il, args: CCJ(il, args, il.compare_unsigned_less_than(8, R(il, args[0]), R(il, args[1]))),
    "J.AE": lambda il, args: CCJ(il, args, il.compare_unsigned_greater_than(8, R(il, args[0]), R(il, args[1]))),
    "LEA": lambda il, args: LEA(il, args),
}
