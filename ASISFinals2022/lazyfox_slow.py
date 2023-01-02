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
# should be [86,4137618786,842065532,2238157509,2995688660,3894547409, 3236831899,241116835,61235420,1729609860,3858064586,235877251]