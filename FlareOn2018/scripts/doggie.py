import string

def calcHammingDistance(a, b):
    return sum([((a^b)>>i)&1 for i in range(8)])
def calcHammingStr(a,b):
    return sum([calcHammingDistance(ord(a[i]), ord(b[i])) for i in range(min(len(a), len(b)))])+abs(len(a)-len(b))*8
def repeatXOR(a, b): return ''.join([chr(ord(a[i])^ord(b[i%len(b)])) for i in range(len(a))])

f = open("doogie.bin", "rb")
data = f.read()
f.close()

data = data[0xA09:0xEA3] #data that gets decrypted

data = repeatXOR(data, "\x19\x90\x02\x06") #based on the hint of Februrary 06, 1990

hamming = sorted([(keysize, float(sum([calcHammingStr(data[keysize*(i*2):keysize*(i*2)+1],data[keysize*(i*2+1):keysize*(i*2+1)+1]) for i in range((len(data)/keysize))]))/(len(data)/keysize)) for keysize in range(2, 68)], key = lambda x : x[1])

likely_length = hamming[0][0]
print("Most likely length of key: "+str(likely_length))

highest = [0]*likely_length
highest2nd = [0]*likely_length
lowest  = [0xFF]*likely_length
lowest2nd  = [0xFF]*likely_length

for i,d in enumerate(data):
    v = ord(d)
    idx = i%likely_length
    if v > highest[idx]:
        highest2nd[idx] = highest[idx]
        highest[idx] = v
    if v < lowest[idx]:
        lowest2nd[idx] = lowest[idx]
        lowest[idx] = v

for i in range(likely_length):
    possible = []
    for c in [chr(lowest[i]^ord('\n')),chr(lowest[i]^ord('\r')),chr(highest[i]^ord('\n')),chr(highest[i]^ord('\r'))]:
        if c in string.letters: 
            possible.append(c)
    print(str(i)+": "+str(possible))