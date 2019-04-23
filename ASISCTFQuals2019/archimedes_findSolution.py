import string
import zipfile

map = {}

# read the lists from a zip archive
archive = zipfile.ZipFile('rnums.zip', 'r')

encryptedData = []
with open("flag.enc", "rb") as flag: # read the flag
    encryptedData = [ord(c) for c in flag.read()]

# limit the amount of entries to parse
UPPERBORDER = 0x1000

# evaluate the lists from the archive and map them to their index
for i in range(1,UPPERBORDER):
    try:
        map[i] = eval(archive.read('entry_%04X.txt' % i))
    except:
        pass
archive.close()

print("Parsed..")

# try the encryption key lists on the flag
for i in range(1,UPPERBORDER):
    if not i in map: continue
    d = [chr(map[i][j]^encryptedData[j]^0x8F^j) for j in range(len(encryptedData))] # same code as in the binary, as it only uses xor it's symmetrical
    if(all([c in string.printable for c in d])): # print everything with the index that doesn't contain not-printable character
        print ("[%04X]: "%i)+''.join(d)
print("Done..")