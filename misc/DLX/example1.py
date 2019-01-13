from DLXemu import *

# Example for calculating the greatest common divisor using DLX Assembly

example = """
;       
;       Euclidean algorithm
;     
;       Input
;       100 = first number
;       104 = second number
;
;       Register Setup
;       R1  = first number
;       R2  = second number
;       R3  = temporary value
;       R4  = Stack Pointer
;       ====================
;       R1  = Result
;       108 = Result

        ADDI R4, R0, #1000  ; 00 Set stackpoint to top of the stack
        LW   R1, 100(R0)    ; 04 Read the first parameter
        LW   R2, 104(R0)    ; 08 Read the second parameter
        JAL  GCD            ; 0C Call subprogramm
        SW   108(R0), R1    ; 10 Save result
        HALT                ; 14 Halt Emulator
        
GCD:    SW   0(R4), R31     ; 18 Push return value onto the stack
        ADDI R4, R4, #4     ; 1C Increase stack pointer
        SUB  R3, R1, R2     ; 20 Check if R1 and R2 are equal
        BEQZ R3, done       ; 24 Jump to the end of the function if done
        SLT  R3, R1, R2     ; 28 Check if the order of the numbers is correct
        BEQZ R3, gcdF       ; 2C jump if the order is correct
        ADD  R3, R0, R1     ; 30 Exchange R1 and R2 if order is incorrect
        ADD  R1, R0, R2     ; 34
        ADD  R2, R0, R3     ; 38
gcdF:   SUB  R1, R1, R2     ; 3C Subtract the smaller number from the bigger one
        JAL  GCD            ; 40 Recursively call GCD again
done:   SUBI R4, R4, #4     ; 44 Decrease stack pointer
        LW   R31, 0(R4)     ; 48 Pop return value from the stack
        JR   R31            ; 4C Return to caller function
"""

emu = EmulatorContext()

emu.writeWord(100, 1102452)
emu.writeWord(104, 98938)

execute(example,emu=emu,trace=True) #execute the example code with a given emulator

print("================================")
print("GCD: "+str(emu.regs.R[1]))