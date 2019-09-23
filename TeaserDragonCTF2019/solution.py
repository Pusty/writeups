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
    
print(getFlag())
print(algorithm(getFlag()[6:22]))