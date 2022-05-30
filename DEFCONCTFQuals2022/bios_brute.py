import lzma

orig = open("flag.lzma.enc", "rb")
dataOrig = orig.read()
orig.close()

def applyRound(key):
    tmp1 = (key >> 0xF)&0xffff
    tmp2 = (key >> 0xA)&0xffff
    tmp3 = (key >> 0x8)&0xffff
    tmp4 = (key >> 0x3)&0xffff
    return ((key << 1) | ((tmp1 ^ tmp2 ^ tmp3 ^ tmp4) & 1))&0xffffffff

firstBytes = list(dataOrig[0:4])
shouldBe   = [0x5d, 0x00, 0x00, 0x80] # header from the other lzma images

# bruteforce key
for a in range(10):
    for b in range(10):
        for c in range(10):
            for d in range(10):
                for e in range(10):
                
                    # check if the first 4 bytes match with the assumed header after decryption
                    key = a+b*10+c*100+d*1000+e*10000
                    failed = False
                    for i in range(4):
                        key = applyRound(key)
                        if(dataOrig[i]^(key&0xff) != shouldBe[i]):
                            failed = True
                            break
                            
                    # if the header matched, fully decrypt and try to decompress using the LZMADecompressor
                    if not failed:
                        print(e, d, c, b, a)
                        dataTry = []
                        key = a+b*10+c*100+d*1000+e*10000
                        for q in dataOrig:
                            key = applyRound(key)
                            dataTry.append(q^(key&0xff))
                        dataTry = bytes(dataTry)
                        try:
                            dec = lzma.LZMADecompressor()
                            print("Decompress:", dec.decompress(dataTry, max_length=32))
                            # Save the decrypted files
                            f = open("flag."+str(a+b*10+c*100+d*1000+e*10000)+".lzma", "wb")
                            f.write(dataTry)
                            f.close()
                        except Exception as e:
                            pass