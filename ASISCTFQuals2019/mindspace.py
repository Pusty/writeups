import math

def doubleToStringFancy(dValue): # 00000000000024B8
    intValue = 2 * int(math.floor(round(100000.0 * dValue)))
    if dValue < 0.0:
        intValue = ~intValue
    res = ""
    continueExec = True
    while continueExec:
        continueExec = (intValue >> 5) > 0
        v4 = intValue&0x1F
        if continueExec:
            v4 |= 0x20
        res = res + chr(v4+0x3F)
        intValue = intValue >> 5
    return res
    
def transformValues(pva): # 000000000000257A
    lastValue = 0.0
    lastValue2 = 0.0
    mainString = ""
    for pv in pva:
        mainString = mainString + doubleToStringFancy(pv[0] - lastValue)
        mainString = mainString + doubleToStringFancy(pv[1] - lastValue2)
        lastValue = pv[0]
        lastValue2 = pv[1]
    
    return mainString
    
    
def parseLine(content, index=1): # 0000000000002B35
    findComma = content.index(", ")
    tillComma = content[0:findComma]
    content = content[findComma+2:]
    upperValue = float(content) - 80.0 - index
    lowerValue = index + float(tillComma) - 80.0
    if lowerValue > 90.0 or lowerValue < -90.0:
        print(tillComma)
        print("LOWER VALUE OUT OF RANGE")
        return None
    if upperValue > 180.0 or upperValue < -180.0:
        print(content)
        print("UPPER VALUE OUT OF RANGE")
        return None
    return (lowerValue, upperValue)
    
    
def fancyToDouble(res): # revert the byte array to the floating point number that created it
    intValue = 0
    index = 0
    continueExec = True
    cList = []
    while continueExec: # just a reverse implementation of the original
        cur = ord(res[index])-0x3F
        if cur&0x20 == 0:
            continueExec = False
        else:
            cur = cur ^ 0x20
        cList.append(cur)
        index += 1
    cList.reverse()
    for e in cList:
        intValue |= e
        intValue = intValue << 5
    intValue = intValue >> 5
    # return multiple values as the rounding and negating part cause multiple possible inputs
    return ([float(intValue / 2) / 100000.0, (float(intValue / 2) + 1) / 100000.0, (float(intValue / 2) - 1) / 100000.0, float((~intValue) / 2) / 100000.0, (float((~intValue) / 2) + 1) / 100000.0, (float((~intValue) / 2) - 1) / 100000.0], index)

def untransformValues(str):
    lastValue = 0.0
    lastValue2 = 0.0
    
    bigIndex = 0
    bL = []
    
    while len(str) > 0:
        res, index = fancyToDouble(str) # decode the possible values and amount of characters parsed
        part = str[:index] # extract the first part
        str = str[index:] # remove the first part from the string
        res2, index = fancyToDouble(str) # decode the possible values and amount of characters parsed
        part2 = str[:index] # extract the second part as it's partly independent of the first
        str = str[index:] # remove the second part from the string
        bigIndex += 1 # increase the index needed for decoding
        
        for r in res+[]: # filter the ones out that don't encode to the same byte array
            if(doubleToStringFancy(r) != part):
                res.remove(r)
        
        res = [r+lastValue for r in res] # reconstruct to the original state
                
        for r in res2+[]: # filter the ones out that don't encode to the same byte array
            if(doubleToStringFancy(r) != part2):
                res2.remove(r)
            
        res2 = [r+lastValue2 for r in res2] # reconstruct to the original state
            
        if len(res) > 1 or len(res) == 0: # exit if multiple results or possible or non was found
            print("Error with line 1")
            print(res)
            return bL
            
        if len(res2) > 1 or len(res2) == 0: # exit if multiple results or possible or non was found
            print("Error with line 2")
            print(res2)
            return bL
            
        lastValue = res[0]
        lastValue2 = res2[0]
        bL.append(((res[0] + 80.0 - bigIndex),(bigIndex + (res2[0]) + 80.0))) # append the decoded values to the array
    return bL    

    
def unparse(st):
    l = untransformValues(st) # turn the encrypted content back into 
    res = ""
    for p in l:
        res = res + ("%0.5f, %0.5f\n" % (p[0],p[1])) # put the reconstructed values in the correct format
    res = res[:-1]
    print res # print the reconstructed file
    # parse all the recontructed lines to verify the result is correct
    i=1
    cL = []
    for line in res.split("\n"):
        cL.append(parseLine(line, index=i))
        i += 1
    # verify the original and the result of the reconstructed values are the same
    return (transformValues(cL).encode("hex") == st.encode("hex"))
        
# testing encoding
print(parseLine("1.78, 2.5"))
print(parseLine("1.12321321, 2.5", index=2))
print(transformValues([parseLine("1.78, 2.5"), parseLine("1.12321321, 2.5", index=2), parseLine("98.7654321, 133.7420", index=3)]).encode("hex"))

# decode flag
flagFile = open("flag.txt.enc", "rb")
flag = flagFile.read()[:-1] # cut off the last byte "0A" as it's junk data, needs to be adjusted for custom input
flagFile.close()

print(unparse(flag))

