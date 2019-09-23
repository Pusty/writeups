# ummmfpu

    Description:
    So I found this Micromega FPU in my drawer, connected it to an Arduino Uno and programmed it to validate the flag.
    
"ummmfpu" provides an Arduino File for loading code onto a Micromega FPU v3.1, the code loaded onto the FPU and a screenshot of an example serial connection to it.

## Solution

Looking online I wasn't able to find any toolchain for working with the Micromega FPU v3.1 outside of its official IDE which relies on a connection to an actual device.
So my first step was to write an emulator following the more or less good documented specifications from the manufacture:

- http://micromegacorp.com/downloads/documentation/uMFPU-V3_1%20Datasheet.pdf
- http://micromegacorp.com/downloads/documentation/uMFPU-V3_1%20Instruction%20Set.pdf

I mostly only implemented the instructions actually executed by the program and for the string/serial interaction I only wrote provisionally code as it was enough for solving this challenge.

Using my emulator / disassembler I created traces of execution, though because of the usage of self modifying code I had to filter out some of it to reduce the noise and focus on the actual program.


### Self Modifying Code

The program calls a routine at 0250 multiple times during execution, this function creates new functions at runtime to read and write EEPROM to modify code.
First the function writes `80XXDD03` (EELOADA XX; RETURN) to address 03FC where they replace the XX with the address to read, execute the function at 03FC, xor the read data with a key specified at the call to 0250, write `80XXDB03` (EESAVEA XX; RETURN) to address 03FC, again replacing XX with the previous address and call it to write the decrypted function back in EEPROM.
This is repeated for a range of memory for each call to 0250. Once the emulator worked this wasn't interesting anymore though and thus cut from the traces.
(The full execution trace of it is contained in the full_trace.txt file if anyone is still interested)


### First input checks

Here is a commented extract of the trace for checking the first 6 characters and the last one:

```
[0037] : NOP
[0038] : READVAR 14                   ; Read the amount of characters in the serial buffer
[003A] : SELECTA 0                    ; Select the length
[003C] : LUCMPI 17                    ; Check if the amount of characters matches 0x17
[0041] : BRA 10 4E                    ; Jump if not true, that's what I assume at least, I didn't find the conditional code 0x10 in the manual and didn't implement it, which makes us pass these checks either way
[0041] : STRSEL 0 6                   ; Select characters 0-5 of the input
[0044] : STRCMP DrgnS{                ; Compare them to the string "DrgnS{"
[004B] : NOP
[004F] : BRA 10 40                    ; Exit checks if they don't match
[004F] : STRSEL 22 1                  ; Select the 22th character
[0052] : STRCMP }                     ; Compare if it matches "}"
[0054] : NOP
[0058] : BRA 10 37                    ; Again exit, if it doesn't match
```

After this only the character range 6-21 is checked.


### Password calculations

Now following the initial checks the 16 characters in between are read into register 40 to 55.

Then some constant values are written into the registers 72 to 87:

```
[00F4] : SELECTX 72
[00F6] : WRBLK 16 [2061862146, 582495567, 1026097401, 322416505, 271460118, 1849567085, 229339736, 742561068, 1926465691, 286122480, 1486919889, 2032338229, 936396401, 157659013, 328308134, 728970594]
```

A 4x4 matrix is created containing the registers 40 to 55, the matrix is then transposed, a scalar of 3 is added to it and some further calculations are run on it.
If the result of the calculations is 1 the flag is correct, if not the flag is considered wrong. (Addresses 0192 - 0214 contain the calculation code, 007B contains the final deciding comparison)

I've translated the algorithm into python:

```python
def algorithm(password):
    # Check length
    if len(password) != 16:
        print("Character length isn't correct")
        return -1
    # Create matrix
    matrix = [ord(c) for c in password]
    # Transpose 4x4 matrix
    matrix = [matrix[(i%4)*4+(i/4)] for i in range(16)]
    # Add Scalar of 3 to matrix
    matrix = [matrix[i]+3 for i in range(16)]
    # Constants
    constants = [2061862146, 582495567, 1026097401, 322416505, 271460118, 1849567085, 229339736, 742561068, 1926465691, 286122480, 1486919889, 2032338229, 936396401, 157659013, 328308134, 728970594]
    # Start Values
    r3 = 0xA5A5A5A5
    r12 = 0
    # Apply the calculation for all 16 characters
    for i in range(16):
        r3 = r3 * 0x41C64E6D
        r3 = r3 + 0x00003039
        r3 = r3 & 0x7FFFFFFF
        r6 = matrix[i] << 8
        r7 = matrix[i] << 16
        r8 = matrix[i] << 24
        r0 = ((matrix[i] | r6 | r7 | r8) & 0xFFFFFFFF) # with matrix[i] = 0x42, r0 now 0x42424242
        r0 = r0 ^ r3                                   # xor r0 with the current calculated value of r3
        r0 = constants[i] ^ r0                         # xor r0 with the constant of index i
        r12 = r12 | r0                                 # change r12 if this is 0 then everything is correct with the byte
    r12 = r12 + 1
    return r12 == 1
```

### Reversing the password check

The following algorithm means for each character that if `(character repeated 4 times as a number)^r3^constants[i] == 0` is true then it's correct.

Based on that I wrote the following function which prints out the flag including the strings checked at the beginning:

```python
def getFlag():
    values = [0] * 16
    constants = [2061862146, 582495567, 1026097401, 322416505, 271460118, 1849567085, 229339736, 742561068, 1926465691, 286122480, 1486919889, 2032338229, 936396401, 157659013, 328308134, 728970594]
    r3 = 0xA5A5A5A5
    for i in range(len(values)):
        r3 = r3 * 0x41C64E6D
        r3 = r3 + 0x00003039
        r3 = r3 & 0x7FFFFFFF
        values[i] = (r3^constants[i])&0xFF                  # calculate the characters through simple xoring the values
    matrix = [values[(i%4)*4+(i/4)] for i in range(16)]     # invert the transposing by transposing again
    matrix = [matrix[i]-3 for i in range(16)]               # add the inverse of the scalar (so -3)            
    return ("DrgnS{"+''.join([chr(c) for c in matrix])+"}") # add start and ending and return it
```
```

>>> print(getFlag())
    DrgnS{uMFlagPwningUnit}
>>> print(algorithm(getFlag()[6:22]))
    True
```

