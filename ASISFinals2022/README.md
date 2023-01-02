# Lazy Fox

    A Lazy fox can never win over a brown dog and jump over it.
    
Lazy Fox provides a Linux binary and a output_reducted.c file. When running the binary it will generate output similar to the provided C file.

## Solution

The binary reads 4 bytes either from `/dev/urandom` or if provided the file given as the first argument.
These bytes are used as a random seed to generate a longer random seed of 11 32-bit numbers.
This random seed (together with the hard coded `seed[0] = 86`) is then used to generate random numbers to encrypt the input provided in stdin.

An example of a possible output (in this case the initial 4 byte seed are all zero and the input is "A..Z" repeated):

```
#ifdef W
86U,4137618786U,842065532U,2238157509U,2995688660U,3894547409U,
3236831899U,241116835U,61235420U,1729609860U,3858064586U,235877251U,
#endif

#ifndef W
#define W
#include <stdio.h>
typedef unsigned int _;_ J[]={
#include __FILE__
#undef W
0},G,F,l[256],I[256],A,y,m,D,e,R,h;_*w(){if(!G--){y+=++m;for(h=0;h<256;y=l[h++]
=I[255&(R>>10)]+e){A^=(h&1)?A>>((h&2)?16:6):A<<((h&2)?2:13);e=I[h];R=I[h]=I[255
&(e>>2)]+(A+=I[(h+128)&255])+y;}G=255;}return&l[G];}_*X(){for(F=0;256>F;I[F++]=
0);for(F=0;sizeof(J)/sizeof(_)>F;F++)I[F&255]^=J[F];for(A=y=m=G=F=0;F<1<<24;++F
)w();D=F=0x0;return&F;}char*S,s[]="ASIS{7_i<gSp@KuKbW=y5A+@S@'KW2Z_|Gzk3`<liC2"
"yR6pyn=nTAC})qb?pSVt0oC~iAp@*e/Y*OTUJVD{8A&NWP4c`blEIWn?p&{_>w6NlNF+B<-A/_aef"
"GJR'v*oda7o5w73HA|rUQV-M9.?Mzpo3V{E5J3Xgz|1,GX8b}zPx`3.liMNAO(0;o;=Ar~EUUkzH9"
";z`Jg)M@aEzU&*3B5xU)ktJ&BS:Jlk3:=`p4dasoy@WvOE5L:20+H,hH|,5F:C(7s)_G9{Wy(b0@&"
"vD/PmxMTXs3y-eZtU?Z__Fj7@=I;._dPv7c5Ay{6&64/hg`rkBfGzLfp;(w5jnr&S@a_EI'D#q^eo"
"~_vzs";main(){X();for(S=s+*J;*S>37;){for(h=0;h<5;h++){D*=85;D+=(*S++-6)%89;};D
^=*w();for(h=0;h<4;h++){s[F++]=D&255;D>>=8;}}return!fwrite(s,F-*S%5,1,stdout);}
#endif
```

An interesting observation in the binary is that the pseudo random number generator used to generate the expanded seed is the same that takes the expanded seed as input.
This means we don't actually need to reverse it and instead can just use the implementation used in the output C files.

Out of personal preference (rewriting things helps me understand them better) here is the initial python version (lazyfox_slow.py):

```python
G = 0
F = 0
key_stream = [0] * 256
key_state = [0] * 256
key_output = 0
key_offset = 0
key_modulus = 0
e = 0
R = 0

def generate_keystream(output=True):
    global G, F, key_stream, key_state, key_output, key_modulus, key_offset, e, R
    oldG = G
    G = G - 1
    if (oldG == 0):
        key_modulus += 1
        key_modulus &= 0xffffffff
        key_offset += key_modulus
        key_offset &= 0xffffffff
        temp = 0
        while ( temp <= 0xFF ):
            if ( temp & 1 ):
                if ( temp & 2 ):
                    v1 = 16
                else:
                    v1 = 6
                v2 = key_output >> v1
            else:
                if ( temp & 2 ):
                    v3 = 2
                else:
                    v3 = 13
                v2 = key_output << v3
            key_output ^= v2
            e = key_state[temp]
            v4 = key_state[(e >> 2)&0xff]
            key_output += key_state[(temp + 0x80)&0xff]
            key_output &= 0xffffffff
            v5 = temp
            key_state[temp] = (key_output + v4 + key_offset)&0xffffffff
            R = key_state[v5]
            v6 = key_state[(R >> 10)&0xff]
            v7 = temp
            temp += 1
            key_stream[v7] = (e + v6)&0xffffffff
            key_offset = key_stream[v7]
        G = 255
    if output:
        return int.from_bytes(b''.join([(k).to_bytes(4, byteorder="little") for k in key_stream])[G<<2:(G<<2)+4], byteorder="little")


def initialize_keystream(seed=[]):
    global G, F, key_stream, key_state, key_output, key_modulus, key_offset, e, R
    for F in range(0x100):
        key_state[F] = 0
    for F in range(len(seed)):
        key_state[F] = seed[F]

    F = 0
    G = 0
    key_modulus = 0
    key_offset = 0
    key_output = 0
    for F in range(0x1000000):
        generate_keystream(False)
    
def decrypt(seed, ciphertext):
    initialize_keystream(seed)
    D = 0
    index = seed[0]
    output = ""
    while(ord(ciphertext[index]) > 37):
        for i in range(5):
            r = ord(ciphertext[index])
            index += 1
            D *= 85
            D += ((r - 6)&0xff) % 89
            D &= 0xffffffff
        D ^= generate_keystream()
        for i in range(4):
            output += chr(D&0xff)
            D = D >> 8
    return output


def generateSeedList(initialSeed):
    initialize_keystream([initialSeed])
    return [86] + [generate_keystream() for i in range(11)]

print(generateSeedList(0))
```

Of course this is painfully slow.
Using numba and some optimization makes way faster (lazyfox.py)

```python
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
```

With this we can try to decrypt for a given seed in 0.07s!
But wait, our search space is 2^32 and we can only try 14 seeds a second.
This would take 83514 hours (on one thread) to compute...

At this point we tried optimizing it further, finding some weaknesses where we can skip computing parts, reimplementing it in other languages but we never moved from ~0.07s per seed.
As of now the challenge also had 0 solves so nobody else seems to have a plan.

Skipping a few hours in the future, past a lot of planning on whether it is possible to rent enough cloud servers to compute this during the ctf and how much that would cost, luckily a "fixed" version was released.

The "fixed" version instead only read 2 bytes from `/dev/urandom` or the provided file as the initial seed.
This reduced the search space to 2^16 which even on a single thread would only take 1.2 hours.
So a lot of us ran the script for different number ranges and very quickly we finally had the solution:

`27362 b'ASIS{A_qu!cK_bR0wM_fOx_juMp5_ov3R_7He_lAzY_dOg!}'`