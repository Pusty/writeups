import numba
import numpy as np


@numba.jit
def jit_generate_keystream(key_stream, key_state, mergedFields):
    oldG = mergedFields[0]
    mergedFields[0] = mergedFields[0] - 1
    if (oldG == 0):
        mergedFields[3] += 1
        mergedFields[3] &= 0xffffffff
        mergedFields[2] += mergedFields[3]
        mergedFields[2] &= 0xffffffff
        temp = 0
        while ( temp <= 0xFF ):
            if ( temp & 1 ):
                if ( temp & 2 ):
                    v1 = 16
                else:
                    v1 = 6
                v2 = mergedFields[1] >> v1
            else:
                if ( temp & 2 ):
                    v3 = 2
                else:
                    v3 = 13
                v2 = mergedFields[1] << v3
            mergedFields[1] ^= v2
            e = key_state[temp]
            v4 = key_state[(e >> 2)&0xff]
            mergedFields[1] += key_state[(temp + 0x80)&0xff]
            mergedFields[1] &= 0xffffffff
            v5 = temp
            key_state[temp] = (mergedFields[1] + v4 + mergedFields[2])&0xffffffff
            R = key_state[v5]
            v6 = key_state[(R >> 10)&0xff]
            v7 = temp
            temp += 1
            key_stream[v7] = (e + v6)&0xffffffff
            mergedFields[2] = key_stream[v7]
        mergedFields[0] = 255

def generate_keystream():
    global key_stream, key_state, mergedFields
    jit_generate_keystream(key_stream, key_state, mergedFields)
    return int.from_bytes(b''.join([(int(k)).to_bytes(4, byteorder="little") for k in key_stream])[mergedFields[0]<<2:(mergedFields[0]<<2)+4], byteorder="little")

@numba.jit
def jit_initialize_keystream(key_stream, key_state, mergedFields):
    for F in range(0x10000):
        jit_generate_keystream(key_stream, key_state, mergedFields)
        mergedFields[0] = 0
    

def initialize_keystream(seed=[]):
    global key_stream, key_state, mergedFields
    
    key_stream.fill(0)
    key_state.fill(0)
    mergedFields.fill(0)
    
    for F in range(len(seed)):
        key_state[F] = seed[F]
    
    jit_initialize_keystream(key_stream, key_state, mergedFields)

    return (key_stream, key_state, mergedFields)

@numba.jit
def jit_decode(D, ciphertext, index):
    for i in range(5):
        r = ciphertext[index]
        index += 1
        D *= 85
        D += ((r - 6)&0xff) % 89
        D &= 0xffffffff
    return D
            
def decrypt(seed, output, ciphertext):
    initialize_keystream(seed)
    D = 0
    index = seed[0]
    outindex = 0
    output.fill(0)
    while(ciphertext[index] > 37):
        D = jit_decode(D, ciphertext, index)
        index += 5
        D ^= generate_keystream()
        for i in range(4):
            output[outindex] = D&0xff
            if (D&0xff) > 0x7f: return output # invalid decryption return early
            outindex += 1
            D = D >> 8
    return output


def generateSeedList(initialSeed):
    initialize_keystream([initialSeed])
    return np.array([86] + [generate_keystream() for i in range(11)])


# cipher text from output_reducted_new.c
ciphertext = ["ASIS{7_i<gSp@KuKbW=y5A+@S@'KW2Z_|Gzk3`<liC2",
"yR6pyn=nTAC})qb?pSVt0oC~iAp@*e/Y*OTUJVD{8A&`Z2=f2>Po-)f(t9>8+*o2E?ur;+'1D;k-G",
"WIJlw'sr3gy4}6HWP/XgV*i2YiOGDQi!e]jlx_nfhgwiv^{{]jvmhh}smvbrwchb^my]flesfwuih",
"ba~_h"]


ciphertext = list(bytes(''.join(ciphertext), "utf-8"))
ciphertext = np.array(ciphertext)
print(len(ciphertext)//5*4)

key_stream = np.zeros(256, dtype='u4') 
key_state =  np.zeros(256, dtype='u4') 
mergedFields =  np.zeros(4, dtype='u4') 

import time, sys

if len(sys.argv) < 2:
    exit(1)

start_time = time.time()
outputBuffer = np.zeros(256, dtype='u4') 
for i in range(int(sys.argv[1]), int(sys.argv[1]) + 10000):
    if i % 100 == 0:
        sys.stderr.write(str(i) + "\n")
    seed = generateSeedList(i)
    out = decrypt(seed,outputBuffer,ciphertext)
    out = b''.join([bytes([o]) for o in out])
    if b"ASIS" in out:
        print(i, out)
    
print("--- %s seconds ---" % ((time.time() - start_time)/10000))
