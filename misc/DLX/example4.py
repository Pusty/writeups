from DLXemu import *

# Example of writes and reads

example = """
    LW  R1, 100(R0)
    SW  104(R0),R1
    SH  108(R0),R1
    SB  112(R0),R1
    SF  116(R0),F1
    
    LHU R2, 108(R0)
    SW  120(R0),R2
   
    LH  R2, 108(R0)
    SW  124(R0),R2
    
    ;SW  101(R0), R1 ;Illegal Operations
    ;SW  102(R0), R1 ;Illegal Operations
    ;SW  103(R0), R1 ;Illegal Operations
    SW  104(R0), R1
    ;SH  101(R0), R1 ;Illegal Operations
    SH  102(R0), R1
    ;SH  103(R0), R1 ;Illegal Operations
    SH  104(R0), R1
    SB  101(R0), R1
    SB  102(R0), R1
    SB  103(R0), R1
    SB  104(R0), R1
"""

emu = EmulatorContext()

emu.writeWord(100, -123)

execute(example,emu=emu,trace=True)

print(emu.readWord(104))
print(emu.readWord(108))
print(emu.readWord(112))
print(emu.readWord(116))
print(emu.readWord(120))
print(emu.readWord(124))
