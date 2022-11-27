from Crypto.Cipher import DES3

flagFile = open("./gocrygo_victim_directory/Desktop/flаg.txt.qq", "rb")
flagContent = flagFile.read()
flagFile.close()

iv = flagContent[0:8]
flag = flagContent[8:]

coreDump = open("core", "rb")
data = coreDump.read(0x100000)
coreDump.close()

for keyCandidateIndex in range(0, len(data), 8):
    key = data[keyCandidateIndex:keyCandidateIndex+24]
    try:
        cipher = DES3.new(key, DES3.MODE_CTR, nonce=iv[0:1], initial_value =iv[1:8])
        res = cipher.decrypt(flag)
        if b"hitcon" in res.lower():
            print(key.hex())
            print(res)
            break
    except ValueError as e:
        pass
print("Done.")