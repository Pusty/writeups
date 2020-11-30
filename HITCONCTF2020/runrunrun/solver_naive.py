def solve(idx):
    lvar2 = 1
    lvar3 = 1
    lvar4 = 1
    for lvar1 in range(0, (3**idx)):
        lvar5 = ((lvar3 + (lvar2 * 2)) + (lvar4 * 7))% 31337
        lvar4 = lvar3 
        lvar3 = lvar2
        lvar2 = lvar5
    return lvar2

magic = [98, 32, 84, 253, 217, 18, 92, 22, 112, 138, 147, 46, 168, 229, 31, 149, 72, 94, 191, 124, 21, 176, 10, 104, 154, 213, 235, 25, 237, 61, 18, 15]

flag = ""
for i in range(len(magic)):
    c = chr((solve(i)%0x100) ^ magic[i])
    flag += c
    print(c)
    
print(flag)
    
    
