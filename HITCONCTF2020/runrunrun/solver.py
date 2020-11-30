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


def g(x):
    if x <= 0: return 1
    return g(x-2) + g(x-1)*2 + g(x-3)*7 


magic = [98, 32, 84, 253, 217, 18, 92, 22, 112, 138, 147, 46, 168, 229, 31, 149, 72, 94, 191, 124, 21, 176, 10, 104, 154, 213, 235, 25, 237, 61, 18, 15]

solveArray = [10, 73, 3360, 20638, 28598, 17532, 5671, 17999, 7711, 3071, 22732, 26694, 20457, 1939, 10540, 11722, 24188, 4718, 9952, 24078, 9312, 22526, 30293, 13358, 29098, 19623, 27022, 27759, 9438, 21839, 21043, 6258, 29448]
    
s = ""
for i in range(len(magic)):
    s += chr((solveArray[i]%0x100) ^ magic[i])
print(s)
