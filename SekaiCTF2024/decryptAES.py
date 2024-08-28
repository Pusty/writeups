import pyaes

# flag.txt.enc
CIPHERTEXT = "15 2A 38 82 CD 8A 36 33 54 4D 22 66 5C E5 8A EA 1C B2 5D B2 59 64 7A 7E 6D 70 21 2A DD 24 6B 8E 38 11 45 A3 60 3D CA 8F 12 B6 EC 9C 0F 60 D9 26 E9 2C 83 9F 61 70 0F DC 78 92 59 39 48 C1 E7 C2 6B 5C BA 1C 43 C2 86 80 18 62 15 D2 1E 0B 6B 9E 17 2C 14 C7 41 10 C4 35 FE 78 6F B4 FC DD D4 AA BA DD AA 15 02 B7 F7 77 65 43 F3 78 CC EE 14 CA 53 42 DF 3A EC ED A6 31 4A 81 4D FF BE 4E C6 EF 17 68 D0 9D B1 73 FF 4E 24 BF EC BB 55 F5 AF 7D 7D 6B DF 9F 9A 3B 23 98 B3 A4 B4 1C 26 5F 7A 0D"
CIPHERTEXT = bytes.fromhex(CIPHERTEXT.replace(" ", ""))

IV = bytes.fromhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0")

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

pyaes.AES.rcon = [ 0x13, 0x33, 0x37, 0xba, 0xda, 0x55, 0x66] 
aes = pyaes.AESModeOfOperationCBC(KEY, iv=IV)
decrypted = b''
for i in range(len(CIPHERTEXT)//16):
    decrypted += aes.decrypt(CIPHERTEXT[16*i:16*(i+1)])
print(decrypted)
