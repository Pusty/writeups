import base64
import requests

def repeatingXOR(a, b): return ([chr(ord(a[i])^ord(b[i%len(b)])) for i in range(len(a))])

with open("imageprot", "rb") as file:
    data = file.read()[0x2BF11A:][:88516]
    
data = base64.b64decode(data)

key = requests.get('https://httpbin.org/status/418').content
    
dec = ''.join(repeatingXOR(data, key))
with open("image.jpg", "wb") as file:
    file.write(dec)