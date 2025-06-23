import struct

def rotate_left(x, n):
    width = 8
    return (2**width-1)&(x<<n|x>>(width-n))

def rotate_right(x, n):
    width = 8
    return (2**width-1)&(x>>n|x<<(width-n))
    
class VM:
    def __init__(self, bytecode, reg_count=32):
        self.bytecode = bytecode
        self.registers = [0] * reg_count
        self.memory = list(bytes.fromhex("00000000000000000000000000000000423791a759dabeef01020304691337ac000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
        self.pc = 0xa*9
        self.running = True
        self.compareReg0 = 0
        self.compareReg1 = 0
        self.opcode_pc = 0
        self.depth = 0
        self.stackPointer = 0x100
        
        for i in range(0x10):
            self.memory[i] = ord('A')

    def fetch(self):
        opcode = self.bytecode[self.pc]
        self.pc += 1
        return opcode

    def fetch_operand(self):
        value = struct.unpack_from("<I", self.bytecode, self.pc)[0]
        self.pc += 4
        return value

    def trace(self, msg):
        print(f"  [TRACE] [{(self.opcode_pc//9):04x}] {msg}")

    def run(self):
        while self.running and self.pc < len(self.bytecode):
            opcode_pc = self.pc
            self.opcode_pc = opcode_pc
            opcode = self.fetch()

            if opcode == 0x00:  # ADD
                dst, src = self.fetch_operand(), self.fetch_operand()
                self.trace(f"ADD r{dst}({self.registers[dst]}) += r{src}({self.registers[src]})")
                self.registers[dst] += self.registers[src]
                self.registers[dst] &= 0xffffffffffffffff

            elif opcode == 0x01:  # SUB
                dst, src = self.fetch_operand(), self.fetch_operand()
                self.trace(f"SUB r{dst}({self.registers[dst]}) -= r{src}({self.registers[src]})")
                self.registers[dst] -= self.registers[src]
                self.registers[dst] &= 0xffffffffffffffff

            elif opcode == 0x02:  # MUL
                dst, src = self.fetch_operand(), self.fetch_operand()
                self.trace(f"MUL r{dst}({self.registers[dst]}) *= r{src}({self.registers[src]})")
                self.registers[dst] *= self.registers[src]
                self.registers[dst] &= 0xffffffffffffffff

            elif opcode == 0x03:  # DIV
                dst, src = self.fetch_operand(), self.fetch_operand()
                if self.registers[src] != 0:
                    self.trace(f"DIV r{dst}({self.registers[dst]}) //= r{src}({self.registers[src]})")
                    self.registers[dst] //= self.registers[src]
                    self.registers[dst] &= 0xffffffffffffffff
                else:
                    self.trace(f"DIV by zero! Halting.")
                    self.running = False

            elif opcode == 0x04:  # MOD
                dst, src = self.fetch_operand(), self.fetch_operand()
                if self.registers[src] != 0:
                    self.trace(f"MOD r{dst}({self.registers[dst]}) %= r{src}({self.registers[src]})")
                    self.registers[dst] %= self.registers[src]
                    self.registers[dst] &= 0xffffffffffffffff

            elif opcode == 0x05:  # MOV
                dst, src = self.fetch_operand(), self.fetch_operand()
                self.trace(f"MOV r{dst} = r{src}({self.registers[src]})")
                self.registers[dst] = self.registers[src]
                self.registers[dst] &= 0xffffffffffffffff

            elif opcode == 0x06:  # MOVI
                dst, imm = self.fetch_operand(), self.fetch_operand()
                self.trace(f"MOVI r{dst} = {imm}")
                self.registers[dst] = imm
                self.registers[dst] &= 0xffffffffffffffff

            elif opcode == 0x07:  # CMP
                dst, src = self.fetch_operand(), self.fetch_operand()
                a, b = self.registers[dst], self.registers[src]
                self.trace(f"CMP r{dst}({a}) vs r{src}({b})")
                self.compareReg0 = a&0xffffffff
                self.compareReg1 = b&0xffffffff

            elif opcode == 0x08:  # JE
                dst = self.fetch_operand()
                self.trace(f"JE if compareReg0 == compareReg1 jump to {hex(dst//9)} (compareReg0={self.compareReg0}, compareReg1={self.compareReg1})")
                if self.compareReg0 == self.compareReg1:
                    self.pc = dst
                else:
                    self.pc += 4
                #self.pc = dst

            elif opcode == 0x09:  # JL
                dst = self.fetch_operand()
                self.trace(f"JL if compareReg0 < compareReg1 jump to {hex(dst//9)} (compareReg0={self.compareReg0}, compareReg1={self.compareReg1})")
                if self.compareReg0 < self.compareReg1:
                    self.pc = dst
                else:
                    self.pc += 4
                    
                    

            elif opcode == 0x0A:  # JLE
                dst = self.fetch_operand()
                self.trace(f"JLE if compareReg0 <= compareReg1 jump to {hex(dst//9)} (compareReg0={self.compareReg0}, compareReg1={self.compareReg1})")
                if self.compareReg0 <= self.compareReg1:
                    self.pc = dst
                else:
                    self.pc += 4

            elif opcode == 0x0B:  # JG
                dst = self.fetch_operand()
                self.trace(f"JG if compareReg0 > compareReg1 jump to {hex(dst//9)} (compareReg0={self.compareReg0}, compareReg1={self.compareReg1})")
                if self.compareReg0 > self.compareReg1:
                    self.pc = dst
                else:
                    self.pc += 4

            elif opcode == 0x0C:  # JGE
                dst = self.fetch_operand()
                self.trace(f"JGE if compareReg0 >= compareReg1 jump to {hex(dst//9)} (compareReg0={self.compareReg0}, compareReg1={self.compareReg1})")
                if self.compareReg0 >= self.compareReg1:
                    self.pc = dst
                else:
                    self.pc += 4

            elif opcode == 0x0D:  # STORE
                addr, reg = self.fetch_operand(), self.fetch_operand()
                mem_addr = self.registers[addr]
                value = self.registers[reg]&0xff
                self.memory[mem_addr] = value
                self.trace(f"STORE mem[r{reg} = {mem_addr}] = r{reg}({value})")

            elif opcode == 0x0E:  # LOAD
                reg, addr = self.fetch_operand(), self.fetch_operand()
                mem_addr = self.registers[addr]
                value = self.memory[mem_addr]
                self.trace(f"LOAD r{reg} = mem[r{addr} = {mem_addr}]({value})")
                self.registers[reg] = value

            elif opcode == 0x0F:  # SYSCALL
                self.trace(f"SYSCALL -> halting")
                self.running = False

            elif opcode == 0x10:  # CALL
                target = self.fetch_operand()
                self.trace(f"CALL {hex(target//9)}, push(return addr {hex((self.pc//9)+1)})")
                self.stackPointer += 1
                self.memory[self.stackPointer] = (self.pc//9)+1
                self.depth += 1
                self.pc = target

            elif opcode == 0x11:  # RET
                if self.depth == 0:
                    self.trace(f"RET INTO NOTHING -> halting")
                    self.running = False
                else:
                    self.trace(f"RET to {hex(self.memory[self.stackPointer]*9)}")
                    self.pc = self.memory[self.stackPointer]*9
                    self.stackPointer -= 1
                    self.depth -= 1

            elif opcode == 0x12:  # AND
                dst, src = self.fetch_operand(), self.fetch_operand()
                self.trace(f"AND r{dst} &= r{src} ({self.registers[dst]} &= {self.registers[src]})")
                self.registers[dst] &= self.registers[src]

            elif opcode == 0x13:  # XOR
                dst, src = self.fetch_operand(), self.fetch_operand()
                self.trace(f"XOR r{dst} ^= r{src} ({self.registers[dst]} ^= {self.registers[src]})")
                self.registers[dst] ^= self.registers[src]

            elif opcode == 0x14:  # NOT
                dst = self.fetch_operand()
                self.pc += 4
                self.trace(f"NOT r{dst} = ~r{dst} (~{self.registers[dst]})")
                self.registers[dst] = (~self.registers[dst])&0xffffffffffffffff

            elif opcode == 0x15:  # JMP
                target = self.fetch_operand()
                self.trace(f"JMP to {hex(target//9)}")
                self.pc = target

            elif opcode == 0x16:  # PRINT
                reg, _ = self.fetch_operand(), self.fetch_operand()
                print(f"[PRINT] r{reg} = {self.registers[reg]}")

            elif opcode == 0x17:  # ROR
                dst, amt = self.fetch_operand(), self.fetch_operand()
                val = self.registers[dst] & 0xFF
                shift = self.registers[amt] & 0xFF
                result = rotate_right(val, shift)
                self.trace(f"ROR r{dst}({val}) >> r{amt}({shift}) -> {result}")
                self.registers[dst] = result & 0xff

            elif opcode == 0x18:  # ROL
                dst, amt = self.fetch_operand(), self.fetch_operand()
                val = self.registers[dst] & 0xFF
                shift = self.registers[amt] & 0xFF
                result = rotate_left(val, shift)
                self.trace(f"ROL r{dst}({val}) << r{amt}({shift}) -> {result}")
                self.registers[dst] = result & 0xff

            elif opcode == 0x19:  # SHR
                dst, amt = self.fetch_operand(), self.fetch_operand()
                val = self.registers[dst]&0xffffffffffffffff
                shift = self.registers[amt]
                result = val >> shift
                self.trace(f"SHR r{dst}({val}) >> r{amt}({shift}) -> {result}")
                self.registers[dst] = result

            elif opcode == 0x1A:  # SHL
                dst, amt = self.fetch_operand(), self.fetch_operand()
                val = self.registers[dst]&0xffffffffffffffff
                shift = self.registers[amt]
                result = val << shift
                result &= 0xff
                self.trace(f"SHL r{dst}({val}) << r{amt}({shift}) -> {result}")
                self.registers[dst] = result

            else:
                self.trace(f"Unknown opcode {opcode:#x} at pc {opcode_pc}")
                self.running = False


if __name__ == "__main__":
    bytecode = data0 = bytes.fromhex("0602000000000000000603000000010000000604000000020000000702000000010000000c4800000000000000030000000004000000000200000003000000151b0000000000000012000000000300000011000000000000000006020000000c0000000603000000300000000d03000000020000000600000000000000000603000000310000000d030000000000000010ea000000000000000603000000310000000e00000000030000000604000000010000000000000000040000000604000000300000000e0300000004000000070000000003000000097e000000000000001100000000000000000601000000000000000603000000000000000003000000010000000e04000000030000000602000000010000000003000000020000000602000000100000000403000000020000000e05000000030000000503000000010000000003000000000000000602000000100000000403000000020000000003000000020000000e060000000300000005070000000100000006020000000800000004070000000200000005080000000600000018080000000700000013040000000800000005070000000500000013070000000000000000040000000700000006020000000001000004040000000200000014040000000000000005070000000100000006020000000d0000000207000000020000000602000000080000000407000000020000001704000000070000000607000000320000000d07000000000000000607000000330000000d07000000010000000607000000340000000d07000000020000000607000000350000000d07000000030000000607000000360000000d07000000040000000607000000370000000d07000000050000000607000000380000000d07000000060000000500000000050000000601000000070000001000000000000000000601000000000000000700000000010000000607000000320000000e00000000070000000607000000330000000e01000000070000000607000000340000000e02000000070000000607000000350000000e03000000070000000607000000360000000e04000000070000000607000000370000000e05000000070000000607000000380000000e06000000070000000857030000000000000602000000a50000001304000000020000000607000000320000000d07000000000000000607000000330000000d07000000010000000607000000340000000d07000000020000000607000000350000000d07000000030000000607000000360000000d07000000040000000607000000370000000d07000000050000000607000000380000000d07000000060000000500000000050000000601000000010000001000000000000000000601000000000000000700000000010000000607000000320000000e00000000070000000607000000330000000e01000000070000000607000000340000000e02000000070000000607000000350000000e03000000070000000607000000360000000e04000000070000000607000000370000000e05000000070000000607000000380000000e060000000700000008ad0400000000000006020000003c0000000004000000020000000602000000000100000404000000020000000607000000320000000d07000000000000000607000000330000000d07000000010000000607000000340000000d07000000020000000607000000350000000d07000000030000000607000000360000000d07000000040000000607000000370000000d07000000050000000607000000380000000d07000000060000000500000000050000000601000000020000001000000000000000000601000000000000000700000000010000000607000000320000000e00000000070000000607000000330000000e01000000070000000607000000340000000e02000000070000000607000000350000000e03000000070000000607000000360000000e04000000070000000607000000370000000e05000000070000000607000000380000000e060000000700000008030600000000000006020000007a0000000104000000020000000602000000ff0000001204000000020000000603000000200000000003000000010000000d030000000400000006020000000100000000010000000200000006020000001000000007010000000200000009f3000000000000000601000000000000000603000000100000000602000000050000000202000000010000000003000000020000000103000000000000000602000000100000000403000000020000000602000000200000000003000000020000000e07000000030000000d0100000007000000060200000001000000000100000002000000060200000010000000070100000002000000095406000000000000110000000000000000")
    vm = VM(bytecode)
    vm.run()
    print(vm.memory)