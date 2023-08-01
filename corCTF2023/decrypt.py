import galois
import math
import struct

def inputStuff(s):
    arr = []
    sizeStuff = (1 << ((int(math.log2(len(s)))+1) & 0x3f))
    sl = [s[i] if i < len(s) else 0 for i in range(sizeStuff)]
    for i in range(sizeStuff//2):
        arr.append((sl[i*2] << 8) | (sl[i*2+1]))
    return arr

def outputStuff(arr):
    output = b''
    for i in range(len(arr)):
        output += struct.pack(">H", arr[i]&0xffff)
    return output

def encrypt(s, a, b):
    step0 = inputStuff(s)
    step1 = galois.ntt(step0, modulus=0x10001)
    step2 = [((int(x)*a)+b)%0x10001 for x in step1]
    step3 = galois.ntt(step2, modulus=0x10001)
    step4 = [(int(x)*pow(len(step0), -1, 0x10001))%0x10001 for x in step3]
    step4 = [step4[0]] + step4[1:][::-1]
    return outputStuff(step4)
    
def encrypt(s, a, b):
    step0 = inputStuff(s)
    step1 = galois.ntt(step0, modulus=0x10001)
    step2 = [((int(x)*a)+b)%0x10001 for x in step1]
    step4 = galois.intt(step2, modulus=0x10001)
    return outputStuff(step4)
    
def decrypt(c, a, b):
    ai = int(pow(a, -1, 0x10001))
    return encrypt(c, ai, (-ai*b)%0x10001)
    
def encrypt_fast(s, a, b):
    step0 = inputStuff(s)
    step4 = [((int(x)*a))%0x10001 for x in step0]
    step4[0] = (step4[0]+b)%0x10001
    return outputStuff(step4)
    
def decrypt_fast(c, a, b):
    ai = int(pow(a, -1, 0x10001))
    return encrypt_fast(c, ai, (-ai*b)%0x10001)
    
def brute(ciphertext, plaintext):
    encoded_ciphertext = inputStuff(ciphertext)
    encoded_plaintext = ((plaintext[0]<<8) | plaintext[1]) # encode as short

    for a in range(1, 2**16+1):
        b = (encoded_ciphertext[0] - (encoded_plaintext*a))%0x10001
        decrypted = decrypt_fast(ciphertext, a, b)
        if decrypted.isascii():
            print((a, b), decrypted)
            
            
ciphertext = bytes.fromhex("B6 02 33 3E 27 AB 2E 8D B4 3D 1C E3 0E A1 79 33 FA 5F A8 77 CE 95 D2 47 D1 C6 EB E8 2C 5A 3D A3 E0 D5 89 EF 12 05 2C 5A EF 9E F1 D1 49 36 49 63 61 DC A9 4B E3 91".replace(" ", ""))
brute(ciphertext, b'co')

def solve(ciphertext, plaintext):
    encoded_ciphertext = inputStuff(ciphertext)
    encoded_plaintext_0 = ((plaintext[0]<<8) | plaintext[1])
    encoded_plaintext_1 = ((plaintext[2]<<8) | plaintext[3])
    a = (encoded_ciphertext[1] * pow(encoded_plaintext_1, -1, 0x10001))%0x10001
    b = (encoded_ciphertext[0] - (encoded_plaintext_0*a))%0x10001
    print((a, b), decrypt_fast(ciphertext, a, b))
    
solve(ciphertext, b'corc')