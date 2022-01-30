import json

f = open("metadata.json")
data = json.load(f)

ab = data["arrayBuffer"]

def decode(o, l):
    print("> ", ab[o:o+l])
    o += 2 # skip [array tag] [array size]
    return ''.join([chr(ab[o+i*4+0])for i in range(l)]) # it's all ascii anways so just do this
        
print(decode(9398, 28)) # decodedText
print(decode(9512, 43)) # decodedFlag