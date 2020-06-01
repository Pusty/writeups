def mapi(X, Y, offset=0):
    if Y == X:
        return [[i+offset for i in range(Y)]]
    if X > Y:
        return []
    if X == 0: return [[]]
    return mapi(X, Y-1, offset+1) +  [ [offset]+s for s in mapi(X-1, Y-1, offset+1)]
 
mappings = mapi(18,26)

spaces = [8, 11, 17, 22, 26, 30, 34, 39, 44, 51]
flattened = [[20, 32, 37, 54], [27], [31, 55], [25, 38, 50], [4, 6, 15, 16, 19, 36, 56], [13, 41], [42, 49], [24], [9], [7, 33], [23, 28], [48], [14, 21, 35, 53], [43, 45], [12, 40, 46, 52], [47], [5], [10, 18, 29]]

charset = "abcdefghijklmnopqrstuvwxyz"

l = list(" "*62)
l[0] = 'O'
l[1] = 'O'
l[2] = 'O'
l[3] = '{'
l[57] = '}'

a = 0
print(str(len(mappings))+" Mappings:")
for mapping in mappings:
    for i in range(len(mapping)):
        c = charset[mapping[i]]
        for j in flattened[i]:
            l[j] = c
    print(''.join(l)+" "+str(a))
    a += 1
    
    break # instead of iterating all solving the first with https://quipqiup.com/ is faster
   
# OOO{fyfo nz whuff zfbu pke cpz dbo ufbe whiv vwxqie wubdf}  -> https://quipqiup.com/ solves it within seconds
   
# OOO{even my three year old boy can read this stupid trace}     1374777
    