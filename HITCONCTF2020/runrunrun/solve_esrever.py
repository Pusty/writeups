# linear recursion http://www.math.cmu.edu/~mradclif/teaching/228F16/recurrences.pdf

def mat_mul(A, B):
    C = [[0] * 3 for _ in range(3)]
    for i in range(3):
        for j in range(3):
            for k in range(3):
                C[i][j] += A[i][k] * B[k][j]
                C[i][j] %= p
    return C

def mat_pow(m, x):
    t = m
    r = identity
    while x:
        if x & 1:
            r = mat_mul(r, t)
        t = mat_mul(t, t)
        x >>= 1
    return r


p = 31337
m = [
    [0, 0, 7],
    [1, 0, 1],
    [0, 1, 2],
]

identity = [[1, 0, 0], [0, 1, 0], [0, 0, 1]]

keys = []
for idx in range(33):
    coef = mat_pow(m, 3 ** idx)
    key = (coef[0][2] + coef[1][2] + coef[2][2]) % p
    keys.append(key)
print(keys)
    



