# Sign extend in python
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
    elif size == 64:
        off = off & 0xFFFFFFFFFFFFFFFF
        return off | (-(off & 0x8000000000000000))
    return off

# Matrix mul as in the binary
def mult(m, inp):
    out = []
    for k in range(8):
        a = 0
        for i in range(8):
            a += m[i][k] * inp[i]
        out.append(a)
    return out

# Check whether an input is a key candidate and return the intArray/r value to order it properly
def runCheck(vec):
    # Decrypted matrix dumped at runtime from the binary at address 0x1337208 (they have to be decrypted)
    m = [
        [0xffffffffede5dafe,0xfffffffff5f743dd,0x00000000067b8bda,0x0000000017ff1621,0xffffffffe760a0d9,0x0000000010125448,0x000000000d7e1113,0x0000000008000969],
        [0xffffffffeb0a3540,0xffffffffc88f3a85,0x000000000257f745,0x0000000009c7fd78,0xfffffffffe19c100,0x0000000012267980,0x000000000c8505f6,0x0000000010f9c0b7],
        [0xffffffffd9df8aaa,0xffffffff04d141e9,0x0000000021f324fc,0x0000000019648e56,0x00000000055412ed,0x000000002d5b225c,0x000000001a2343fa,0x000000002dd83916],
        [0xffffffffe5a0af81,0xffffffff5cc74a0f,0x0000000008962a72,0x00000000287392d5,0x0000000000315867,0x0000000016f6d77f,0x0000000014fde34c,0x0000000020dc2c52],
        [0xffffffffdafbdc02,0xfffffffed5a8296b,0x000000000cd46b7c,0x0000000014a3b1ca,0x000000002805c014,0x000000002efa4dc8,0x00000000158fd422,0x00000000396d3f69],
        [0xffffffffcb6b92d2,0x000000000314edfd,0xfffffffffe6a83a7,0x000000000e96bbe0,0xffffffffe7df78e9,0x00000000320c4adb,0x0000000012e0feae,0x000000000f42b54d],
        [0xffffffffc8ebcae5,0xffffffffa166c5b8,0x0000000002317c38,0x000000001bc27472,0xffffffffecd4fb9e,0x000000001e294aef,0x0000000039380937,0x00000000179b36a2],
        [0xffffffffd300432f,0xffffffff2d0c1e3c,0x00000000069f76d9,0x0000000017d259ce,0x0000000000d02195,0x000000002bd9cf95,0x000000001b70eed3,0x00000000426dc286]
    ]
    m2 = [ [0] * 8, [0] * 8, [0] * 8, [0] * 8, [0] * 8, [0] * 8, [0] * 8, [0] * 8]

    # Transpose
    for i in range(8):
        for j in range(8):
            m2[i][j] = signOffset(m[j][i], 64)      
    m = m2

    # At first it does matrix multiplication
    res = mult(m, vec)

    # then it calculates an intArray value which is later used for ordering the parts
    r = signOffset((res[0] + 92) // (vec[0] * 100000000), 32)
    # reject negative values
    if(r <= 0):  return None

    # check that for each vector the following property holds
    # To solve this we try scalars of the left eigenvectors as they 
    # fulfill some ratio property this is verifying.
    # tbh no clue I'm not big brain enough for this math stuff I only rev
    for i in range(8):
        tmp = r * (vec[i] * 100000000) - res[i]
        r23 = (tmp >> 0x1f)
        x = (r23^tmp) - r23
        # values above 0x5c are rejected
        if x > 0x5c:
            return None
    # whooo we have a key candidate 
    return (vec, r)



"""

# Get these from sage with the following input
# sign extended dumped matrix
M = m = Matrix([[-303703298, -168344611, 108760026, 402593313, -413097767, 269636680, 226365715, 134220137], [-351652544, -930137467, 39319365, 164101496, -31866624, 304511360, 210044406, 284803255], [-639661398, -4214144535, 569582844, 426020438, 89395949, 760947292, 438518778, 769145110], [-442454143, -2738402801, 144058994, 678662869, 3233895, 385275775, 352183116, 551300178], [-621028350, -5005366933, 215247740, 346272202, 671465492, 788155848, 361747490, 963460969], [-882142510, 51703293, -26573913, 244759520, -404784919, 839666395, 316735150, 256030029], [-924071195, -1587100232, 36797496, 465728626, -321586274, 506022639, 959973687, 396048034], [-754957521, -3539198404, 111113945, 399661518, 13640085, 735694741, 460386003, 1114489478]])

M = M.transpose() 
M.eigenvectors_left()
"""

# Calculate possible key candidates from the eigenvectors
def solutionsFromEigenvectors():
    # matrix taken from sage
    eigvectors = [(9.99999983497936e7,
      [(1, 0.169491520858711, 0.084745751546947, 0.2881355875831414, 0.288135581541381, 0.847457626194665, 0.711864401602224, 0.2711864305805604)],
      1),
     (2.000000038798546e8,
      [(1, 0.952381012280966, 2.52380974358845, 1.238095290338078, 2.38095253294195, 0.714285692436905, 1.71428579754716, 2.190476355812853)],
      1),
     (3.000000002486778e8,
      [(1, 0.56249999554731, 0.6562499830366, 1.781250008071057, 1.78124998926551, 1.25000000457964, 0.93749998508704, 0.718749983851072)],
      1),
     (3.999999995713364e8,
      [(1, 2.24999981996979, 13.4999990261208, 0.249999948696195, 8.2499992358664, 4.49999968632836, 7.2499994613724, 0.499999967815939)],
      1),
     (4.999999990500059e8,
      [(1, 0.34693878212022, 1.1020408347751, 0.59183675570741, 0.1428571707193, 1.0204081565988, 0.7755102140302, 0.83673471316265)],
      1),
     (5.999999984377138e8,
      [(1, 0.6896552117266, 2.034482866964, 1.96551735699380, 1.9310346670275, 0.3793103236556, 2.0000000738185, 1.86206907715878)],
      1),
     (6.99999998618207e8,
      [(1, 1.5833334555942, 3.500000285201, 1.75000013943522, 4.333333783508, 3.4166668726864, 2.333333445203, 3.91666698372095)],
      1),
     (8.00000001844412e8,
      [(1, 0.6000000012274, 0.899999994546, 0.4333333263700, 0.333333323750, 2.0000000104400, 1.633333338514, 1.19999999876425)],
      1)]

    solutions = []
    for eigvec in eigvectors:
        row = list(*eigvec[1])
        # iterate for some multipliers
        for i in range(1, int(128/max(row))):
            floatVersion = [v*i for v in row]
            intVersion = [round(r) for r in floatVersion]
            # check if key candidate
            checkRes = runCheck(intVersion)
            if checkRes != None:
                solutions.append(checkRes)
    return solutions
    

# This is the main calculation part of the weridify function
def weirdifyPre(arg1):
    if(arg1 >= ord('0') and arg1 <= ord('9')):
        return arg1-ord('0')+0x01
    if(arg1 >= ord('A') and arg1 <= ord('Z')):
        return arg1-ord('A')+0x0B
    if(arg1 >= ord('a') and arg1 <= ord('z')):
        return arg1-ord('a')+0x25
    print("Not supported character "+hex(arg1))
    
# the weirdify function
def weirdify(value, rngSeed, iteration):
    v = weirdifyPre(value)
    # this is a pseudo random number generator
    for i in range(iteration):
        rngSeed = signOffset(((rngSeed * 0x343fd)- 0x613d), 32)
    # which applies a "random" value to weirdify the output
    return (((v + 0xd) + (rngSeed&0xff)) % 0x3e) + 1;

# build a table for the weirdify function to invert it
def generateWeirdifyMap():
    weirdifyMap = {}
    charMap = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    charMap = [ord(c) for c in charMap]

    for i in range(len(charMap)):
        weirdifyMap[chr(charMap[i])] = []


    for i in range(len(charMap)):
        # as the "random" value depends on the position the character is at, 
        # we make a map for each possible character and each position
        for j in range(8*8):
            # The seed "0x1337babe" was dumped at runtime from address 0x1337110
            weirdifyMap[chr(charMap[i])].append(weirdify(charMap[i], 0x1337babe, 1+j))
    return weirdifyMap

# generate a key part for a given key candidate
def keyCandidateToKeyPart(weirdifyMap, combo, offset=0):
    col = combo[0]
    line = ""
    for i in range(8):
        # check whether any character of weirdifyMap
        # has the wanted value at the right offset
        for k in weirdifyMap:
            if(weirdifyMap[k][offset+i] == col[i]):
                line += k
                break
    return line
    

def buildKeyFromKeyCandidates(solutions):
    weirdifyMap = generateWeirdifyMap()
    sortMe = []
    for combo in solutions:
        # get the intArray / r value as we need to sort by it
        r = combo[1]
        # generate key candidate parts for all possible positions
        lines = [keyCandidateToKeyPart(weirdifyMap, combo, o*8) for o in range(8)]
        
        # check that all a key was able to be generates for all positions
        # this is more strict than it has to be 
        # (the key candidate only has to be generatable for it's respective position) 
        # but it works for the right set so it is fine
        ok = True
        for l in lines:
            if len(l) !=8:
                ok = False
                break
        if not ok:
            continue
        
        # add the key with the intArray / r value
        sortMe.append((r, lines))

    # sort by intArray / r value, lowest first
    sortMe = sorted(sortMe, key=lambda x: x[0])
    
    # put together the key
    keyParts = ["" for i in range(8)]
    for i in range(8):
        keyParts[i] = sortMe[i][1][i]  
    key = '-'.join(keyParts)
    
    # flip the buffer around as it was swapped before
    key = key[::-1]
    return key

# generate and verify key candidates using big brain math
solutions = solutionsFromEigenvectors()
# build together a key out of possible candidates
key = buildKeyFromKeyCandidates(solutions)
# gimme key
print(key)