from DLXemu import *

# Example for calculating the Factorial value using DLX Assembly


example = """
;       
;          Factorial calculation
; 
;          Input
;          100  = n
;
;          Register Setup
;          R1   = n
;          R2   = Stack Pointer
;          R3   = k
;          R4   = currentValue
;          ====================
;          2000 = Result

           LW    R1, 100(R0)    ; 00 Read n from memory
           ADDI  R2, R0, #1000  ; 04 Set stackpoint to top of the stack
           XOR   R3, R3, R3     ; 08 Initialize k to 0
           JAL   Factorial      ; 0C Call the factorial calculation sub program
           SW    2000(R0), R4   ; 10 Write result into result memory position
           TRAP #0              ; 14 Stop the emulator
        
Factorial: SW    0(R2), R1      ; 18 Save R1 onto the stack
           SW    4(R2), R3      ; 1C Save R3 onto the stack
           SW    8(R2), R31     ; 20 Save the return address onto the stack
           ADDI  R2, R2, #12    ; 24 Increase the stack pointer by the amount of values pushed
           BNEZ  R1, continue   ; 28 Calculate recursive until R0 reached 0
           ADDI  R4, R0, #1     ; 2C If R0 is 0 set R4 to 1 and return
           J     return         ; 30 Return from the subroutine
continue:  ADD   R3, R1, R0     ; 34 k = n
           SUBI  R1, R1, #1     ; 38 n = n - 1
           JAL   Factorial      ; 3C Recursive call to itself
           MULT  R4, R3, R4     ; 40 currentValue = currentValue * k
return:    LW    R31, -4(R2)    ; 44 Pop the return address from the stack
           LW    R3,  -8(R2)    ; 48 Pop the previous current value from the stack
           LW    R1, -12(R2)    ; 4C Pop the current index from the stack
           SUBI R2, R2, #12     ; 50 Decrease the stackpointer by 3 entries
           JR    R31            ; 54 Return to the caller
"""

emu = EmulatorContext()

emu.writeWord(100, 6) # calculate factorial value of 6

execute(example,emu=emu,trace=True)

print("================================")
print("Factorial: "+str(emu.readWord(2000)))
