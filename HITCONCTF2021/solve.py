# cLEMENCy Fun /o/

MOD = 0x200 # 9 bits instead of the usual 8

# normal rc4 KSA
def ksa(key):
    S = [i for i in range(MOD)]
    j = 0
    for i in range(MOD):
        j = (j + S[i] + key[i % len(key)]) % MOD
        S[j], S[i] = S[i], S[j] 
    return S
    
def rc4modified_encrypt(S, inp):
    out = []
    v18 = 0
    v36 = 0
    for i in range(len(inp)):
        v18 = (v18 + S[i]) % MOD
        S[v18], S[j] = S[i], S[v18] 
        K = S[(S[i] + S[v18]) % MOD]     # so far normal rc4
        v36 = ((inp[i] ^ K) + v36) % MOD # + v36 addition :(
        out.append(v36)
    return out

def rc4modified_decrypt(S, inp):
    out = []
    v18 = 0
    v36 = 0
    for i in range(len(inp)):
        v18 = (v18 + S[i]) % MOD
        S[v18], S[i] = S[i], S[v18] 
        K = S[(S[i] + S[v18]) % MOD]
        out.append((((inp[i]-v36)% MOD) ^ K)) # remove v36 then decode like normal rc4
        v36 = inp[i]                          # next v36 key is last encrypted char
    return out
    
    
    
def encrypt(key, ciphertext):  
    S = ksa(key)
    res = rc4modified_encrypt(S, ciphertext)
    
    return res
    
def decrypt(key, ciphertext):  
    S = ksa(key)
    res = rc4modified_decrypt(S, ciphertext)
    return res
    
# decode 16bit unpacked numbers to 9 bit numbers
def h16to9(inpHex):
    data = bytes.fromhex(inpHex)
    out = []
    for i in range(len(data)//2):
        out.append(data[i*2] + (data[i*2+1] << 8))
    return out
    
# decode 27bit hex number with middle endianess to 3 9 bit numbers
def c27to9(m):
    # sort them based on the stack offset
    keys = []
    for k in m:
        keys.append(k) 
    keys.sort()
    out = []
    # middle endianess!
    for i in range(len(keys)):
        num = m[keys[i]]
        c = num&0x1ff
        num = num >> 9
        a = num&0x1ff
        num = num >> 9
        b = num&0x1ff
        out.append(a)
        out.append(b)
        out.append(c)
    return out
    
# key from D666 in the 16 bit word file, 0x6b33 in the actual memory (dump at runtime also possible)
key = h16to9("2B 01 62 00 BC 00 9C 00 3B 00 34 00 11 01 89 00 44 01".replace(" ", ""))
print("Key in 9-bit words: ", [hex(d) for d in key])

# checks of encrypted result
constMap = {
    0x7fffff7: 0xc7a45e,
    0x7ffffe2: 0x441d6a8,
    0x7fffff1: 0x624e22d,
    0x7ffffee: 0x6f30d11,
    0x7ffffeb: 0x40ff43f,
    0x7ffffdf: 0x4062ee8,
    0x7fffff4: 0x183716f,
    0x7ffffe5: 0x69edf0e,
    0x7ffffe8: 0x7885b66
}

# decode the check values to 9 bit - words
data = c27to9(constMap)
print("Constants in 9-bit words: ", hex(len(data)), [hex(d) for d in data])

# decrypt them with the key
dec = decrypt(key, data)
print("Decrypted Data in 27-bit words: ", [hex(dec[i*3+2] + (dec[i*3+0]<<9) + (dec[i*3+1]<<18)) for i in range(len(dec)//3)])
print("Decrypted Data in 9-bit words: ",[hex(d) for d in dec])
print("Decrypted Data as a String:  ", ''.join([chr(d) for d in dec]))
    
    
"""

In debugger with 0 flag file:

Input only zeros:
> dt 3fffbcd
3fffbcd: 40afe95 4fdeb35 7ffe302 01063e5 - 6e11112 2390ff0 1ca9305 63d86fa
3fffbe5: 479f945 000fc00 0000000 3fffbf7 - 3fffbf7 00061d7 0000000 3fffc00
> db 3fffbcd
3fffbcd: 17f 102 095 0f5 13f 135 1f1 1ff 102 031 004 1e5 - 088 1b8 112 087 08e 1f0 149 072 105 0c3 18f 0fa   .........1.........r....
3fffbe5: 0fc 11e 145 07e 000 000 000 000 000 1fd 0ff 1f7 - 1fd 0ff 1f7 030 000 1d7 000 000 000 1fe 0ff 000   ...~...........0........


data = [0 for i in range(0x1b)]
print(hex(len(data)), [hex(c) for c in data])

dec = encrypt(key, data)
print([hex(dec[i*3+2] + (dec[i*3+0]<<9) + (dec[i*3+1]<<18)) for i in range(len(dec)//3)])
print([hex(d) for d in dec])

dec = decrypt(key, dec)
print([hex(dec[i*3+2] + (dec[i*3+0]<<9) + (dec[i*3+1]<<18)) for i in range(len(dec)//3)])
print([hex(d) for d in dec])

"""