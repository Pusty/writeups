# decrypt

def parseTable(nr):
    table = {}
    f = open("table"+str(nr)+".txt", "r")
    lines = f.read().split("\n")[:-1]
    f.close()
    indx = 0
    for line in lines:
        if indx % 10000 == 0:
            print("Loading Randomized Table", indx, len(lines))
            
        a, b = line.split(" ")
        a = int(a, 16)    
        b = int(b, 16)
        
        # load in variations of the dumped entries with potentially one flipped bit
        for i in range(41):
            c = (b ^ (1 << i))&0xffffffffff
            table[c] = a
            
        table[b] = a
        
        indx += 1
        
    return table

# try to lookup from the table of one-bit flipped values by flipping another bit
# (and potentially undoing one of the ciphertext bitflips)
def tryVariations(table, b):
    for j in range(41):
        c = (b ^ (1 << j))&0xffffffffff
        if c in table:
            return table[c]
    # Log if for some reason no entry was found
    print("Failure at", b)
    return 0
    
    
# Load the tables for the 4 different functions
table0 = parseTable(0)
table1 = parseTable(1)
table2 = parseTable(2)
table3 = parseTable(3)


tableTable = [table0, table1, table2, table3]

print("Tables loaded")

ciphertext = open("flag_enc", "rb").read()

f = open("flag.mp4", "wb")

for j in range(len(ciphertext)//20):

    if j % 10000 == 0:
        print(j, len(ciphertext)//20)

    # Take 4 5-byte blocks out of the cipher text
    bigblock = ciphertext[j*20:(j+1)*20]
    chunk = []
    for i in range(4):
        # Run each 5-byte block through the corresponding look up table
        block = bigblock[i*5:(i+1)*5]
        # decode the bytes to a number
        nm = int.from_bytes(block, byteorder="little")
        chunk.append(tryVariations(tableTable[i], nm))
    # Format the 4 chunks to 10-byte plaintext
    f.write((chunk[0] + (chunk[1]<<20) + (chunk[2]<<40) + (chunk[3]<<60)).to_bytes(10, 'little'))
    
f.close()
print("Done..")