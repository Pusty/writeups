from DLXemu import *

# Example for Floating and Double Calculation


example = """
    ADDI R1, R0, #1
    CVTI2D D4,R1
    ADDI R1, R0, #3
    CVTI2D D5, R1
    DIVD D3, D4, D5
    CVTD2F F1, D3
"""

emu = EmulatorContext()

execute(example,emu=emu,trace=True)

print("================================")
print("Double Result: "+str(emu.regs.D[3*2]))
print("Float  Result: "+str(emu.regs.F[1]))
print("Float and Double Memory the same: "+str(emu.regs.F.memory == emu.regs.D.memory))
