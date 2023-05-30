import os
import os.path
import struct

fileMap = {}
magicSequence = bytes.fromhex("0200000000000000000200000000")


def initDB():
    # iterate all files and extract first few encrypted vm program bytes
    if not os.path.exists("encdb.txt"):
        arr = os.listdir('output')
        log = open("encdb.txt", "w")
        for a in arr:
            print(a)
            f = open("output/"+a, "rb")
            d = f.read(0x3219+(0x1d*3))[0x3219:]
            f.close()
            log.write(a+" "+d.hex()+"\n")
        log.close()

    log = open("encdb.txt", "r")
    for line in log:
        name, data = line.split(" ")
        data = bytes.fromhex(data)
        fileMap[name] = data
        
initDB()

    
# Find all binaries that are not encrypted
def findEntrypoint():
    lst = []
    for key, value in fileMap.items():
        if value[2:16] == magicSequence:
            lst.append(key)
    return lst
        
# TEA implementation as in binary
def tea_decrypt_block(block, key):
    key = struct.unpack("<IIII", key)
    v0, v1  = struct.unpack("<II", block)
    sm = 0xC6EF3720

    for i in range(0x20): 
        v1 = (v1 - ((((v0<<4)+key[2]) ^ (v0+sm) ^ ((v0>>5)+key[3]))&0xffffffff))&0xffffffff
        v0 = (v0 - ((((v1<<4)+key[0]) ^ (v1+sm) ^ ((v1>>5)+key[1]))&0xffffffff))&0xffffffff
        sm = sm + 0x61C88647;

    return struct.pack("<II", v0, v1)

def tea_decrypt(block, key, count):
    output = b''
    for i in range(count):
        output += tea_decrypt_block(block[i*8:(i+1)*8], key)
    return output
        
        
# Bruteforce given a key to find likely continuations
def findCandidate(candidate):
    lst = []
    # TEA key made out of password + hardcoded bytes
    candidate = candidate + bytes.fromhex("381337133a133913")
    for key, value in fileMap.items():
        buffer = value[:16]
        buffer = tea_decrypt(buffer, candidate, 2) 
        # ignore first 2 bytes opcodes are randomized
        if buffer[2:] == magicSequence:
            lst.append(key)
    return lst
    