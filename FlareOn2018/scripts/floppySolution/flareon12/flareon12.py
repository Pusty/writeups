#https://gist.github.com/itsZN/781411170d36adb3197cba86b8653136

from binaryninja import *


import struct

def hexr(a):
    if a == 0x4:
        return 'CharOutput'
    if a == 0x8:
        return 'WriteOutput'
    return hex(a)

# Helper function to make tokens easier to make
def makeToken(tokenType, text, data=None):
    tokenType = {
            'i':InstructionTextTokenType.InstructionToken,
            't':InstructionTextTokenType.TextToken,
            'a':InstructionTextTokenType.PossibleAddressToken,
            's':InstructionTextTokenType.OperandSeparatorToken
    }[tokenType]

    if data is None:
        return InstructionTextToken(tokenType, text)
    return InstructionTextToken(tokenType, text, data)


class Subleq(Architecture):
    name = "subleq"
    address_size = 2
    default_int_size = 2
    max_instr_length = 6 # Each instruction is 3 dwords

    # SP register is required, even if we are not going to use it
    regs = {'sp': RegisterInfo('sp', 2)}
    stack_pointer = 'sp'

    def perform_get_instruction_info(self,data,addr):
        # If we can't decode an instruction return None
        if len(data) < self.address_size*3:
            return None

        # Unpack our operands from the data
        a,b,c = struct.unpack('<3H',data[:self.address_size*3])

        # Create the InstructionInfo object for our instruction
        res = InstructionInfo()
        res.length = self.address_size*3

        if c != 0:
            if b == a:
                # Unconditional branch jumps to integer index c
                res.add_branch(BranchType.UnconditionalBranch, c*self.address_size)
            else:
                # True branch jumps to integer index c 
                res.add_branch(BranchType.TrueBranch, c*self.address_size)
                # False branch continues to next instruction
                res.add_branch(BranchType.FalseBranch, addr + 6)

        return res


    def perform_get_instruction_text(self, data, addr):
        # If we can't decode an instruction return None
        if len(data) < self.address_size*3:
            return None

        # Unpack our operands from the data
        a,b,c = struct.unpack('<3H',data[:self.address_size*3])
        
        tokens = []
        
        # Check for invalid instructions that would crash
        #if b*address_size >= 0x4400 or a*address_size >= 0x4400:
        #    tokens = []
        #    tokens.append(makeToken('i', '{:7s}'.format('invalid')))
        #    return tokens, address_size*3

        # Clear instruction to be less verbose
        # clear [B]
        #el
        if a == b:
            tokens = []
            tokens.append(makeToken('i', '{:7s}'.format('clear')))
            tokens.append(makeToken('t', '['))
            tokens.append(makeToken('a', hexr(b*self.address_size), b*self.address_size))
            tokens.append(makeToken('t', ']'))

        # Normal sub instruction
        # sub [B], [A]
        else:
            tokens.append(makeToken('i', '{:7s}'.format('sub')))
            tokens.append(makeToken('t', '['))

            tokens.append(makeToken('a', hexr(b*self.address_size), b*self.address_size))
            tokens.append(makeToken('t', ']'))
            tokens.append(makeToken('s', ', '))
            tokens.append(makeToken('t', '['))
            tokens.append(makeToken('a', hexr(a*self.address_size), a*self.address_size))
            tokens.append(makeToken('t', ']'))

        
        # Unconditional jump
        # ; jmp C
        if c != 0 and b == a:
            tokens.append(makeToken('s', '; '))
            tokens.append(makeToken('i', '{:7s}'.format('jmp')))
            tokens.append(makeToken('a', hex(c*self.address_size), c*self.address_size))

        # Conditional jump
        # ; jmp C if [B] <= 0
        elif c != 0:
            tokens.append(makeToken('s', '; '))
            tokens.append(makeToken('i', '{:7s}'.format('jmp')))
            tokens.append(makeToken('a', hex(c*self.address_size), c*self.address_size))
            tokens.append(makeToken('s', ' if '))
            tokens.append(makeToken('t', '['))
            tokens.append(makeToken('a', hex(b*self.address_size), b*self.address_size))
            tokens.append(makeToken('t', ']'))
            tokens.append(makeToken('t', ' <= 0'))

        return tokens, self.address_size*3


    # Full LLIL lifting for subleq
    def perform_get_instruction_low_level_il(self, data, addr, il):
        # If we can't decode an instruction return None
        if len(data) < self.address_size*3:
            return None

        # Unpack our operands from the data
        a,b,c = struct.unpack('<3H',data[:self.address_size*3])

        # If this instruction would crash, ignore it
        #if b*self.address_size >= 0x4400 or a*self.address_size >= 0x4400:
        #    il.append(il.nop())
        #    return self.address_size*3

        # A, B, and C as pointers
        addr_a = il.const_pointer(self.address_size, a*self.address_size)
        addr_b = il.const_pointer(self.address_size, b*self.address_size)
        addr_c = il.const_pointer(self.address_size, c*self.address_size)

        # mem[A] and mem[B] pointers
        mem_a = il.load(self.address_size, addr_a)
        mem_b = il.load(self.address_size, addr_b)

        # For a clear instruction just store 0
        if a == b:
            # *B = 0
            store_b = il.store(self.address_size, addr_b, il.const(self.address_size,0))
            il.append(store_b)

        # For normal operation, construct a subtraction
        else:
            # *B = *B - *A
            sub_op = il.sub(self.address_size, mem_b, mem_a)
            store_b = il.store(self.address_size, addr_b, sub_op)
            il.append(store_b)

        # Unconditional jump
        if c != 0 and b == a:
            # goto C
            jmp = il.jump(addr_c)
            il.append(jmp)

        # Conditional jump
        elif c != 0:
            # See if we have marked the True jump target before
            t_target = il.get_label_for_address(Architecture['subleq'],
                    il[il.const_pointer(self.address_size, c*self.address_size)].constant)

            # Create the False jump label
            f_target = LowLevelILLabel()

            # If we have to create a jump IL for the True target
            indirect = t_target is None
            if indirect:
                t_target = LowLevelILLabel()

            less_op = il.compare_signed_less_equal(self.address_size, mem_b, il.const(self.address_size, 0))
            if_op = il.if_expr(less_op, t_target, f_target)
            il.append(if_op)

            # We need to create a jump to the true target if it doesn't exist
            if indirect:
                il.mark_label(t_target)
                jmp = il.jump(addr_c)
                il.append(jmp)

            # Last is the fall though for the false target
            il.mark_label(f_target)

        return self.address_size*3

Subleq.register()


class SubleqView(BinaryView):
    name = "SubleqView"
    long_name = "SubleqView"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture['subleq'].standalone_platform
        
    @classmethod
    def is_valid_for_data(self, data):
        return True
        
    def init(self):
        lenData = len(self.parent_view.read(0,0x1000000))
        self.add_auto_segment(0x00000000, 0x10000, 0x223, lenData, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        self.add_function(0x0000000A)
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0000000A, "main"))
        self.add_function(0x0000FFFF)
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0000FFFF, "exit"))        
        return True
        
    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0x0000000A

SubleqView.register()

def markModifiableCode(bv, func):
    # Loop over all instructions in the function
    for t in (t for bb in func.basic_blocks for t in bb.disassembly_text):
        # Find our sub tokens
        if not t.tokens[0].text.startswith('sub '):
            continue

        addr = t.tokens[2].value
        # Check if the address is in a basic block
        bbs = bv.get_basic_blocks_at(addr)
        if len(bbs) == 0:
            continue

        # Check that this address really is an instruction
        for tt in bbs[0].disassembly_text:
            if addr - tt.address >= 3 or addr - tt.address < 0:
                continue
            # Highlight it and add comments
            bbs[0].function.set_user_instr_highlight(tt.address,
                    HighlightStandardColor.RedHighlightColor)
            bbs[0].function.set_comment_at(tt.address, "Modified by 0x%x"%t.address)
            func.set_comment_at(t.address, "Modifies code at 0x%x"%tt.address)
            break

PluginCommand.register_for_function('Subleq check modifiable code', 'subleq', markModifiableCode)
