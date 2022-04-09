import numpy as np

initData = [
    0x7c59a1115f898c02bdef1e03f8a42971,
    0x1d33f3fce07374372ce572b38b540058,
    0x029c91eb9cab7c67405943e2c746ef8a,
    0xf4be5d2a92c9c93c012da654bc29e00c,
    0x94aedb33a79acde64a901fc9b5e1f7ef,
    0x2fc1c5cad1dbb6754707916c3f4f882c,
    0x7953163b864eca9501e948b96dc61489,
    0xa1ce9b3be90d180288c7af20a872b40f,
    0xf08d70b3923d15702def3a950a3df2ee,
    0xd4941922a13fe572173d73ea5e3d9e45
]

multTable = [
    0x654006A05AD681D0ec32ef2ca379f6ef,
    0xf380c3e496070199646B9980E07FBDE6,
    0x6154BEC0CD734930D005C98621B0A224,
    0x468F22365BD9E2ED0DED12B11AA38888,
    0x603FFACC774E09F2895DD3AA6089713E,
    0x7BB0FFD1D80FB3212868836EDEE04734,
    0x92C103F01E7DDCA6D313806DAD60830A,
    0xBA665904D9CE575BF63D4B112D6FD165,
    0x3B8EFD66D9AB488A4BDA5E346CF43679,
    0xAADC352D973570941C4EF5256BF7691F
]

initData = [d&((2**64)-1) for d in initData]
multTable = [d&((2**64)-1) for d in multTable]

mtx = [
    [0,1,0,0,0,0,0,0,0,0],
    [0,0,1,0,0,0,0,0,0,0],
    [0,0,0,1,0,0,0,0,0,0],
    [0,0,0,0,1,0,0,0,0,0],
    [0,0,0,0,0,1,0,0,0,0],
    [0,0,0,0,0,0,1,0,0,0],
    [0,0,0,0,0,0,0,1,0,0],
    [0,0,0,0,0,0,0,0,1,0],
    [0,0,0,0,0,0,0,0,0,1],
    multTable
]


mtx = np.array(mtx, dtype=np.uint64)
initData = np.array([initData], dtype=np.uint64)

INPUT_VALUE = 2

print((np.matmul(np.linalg.matrix_power(mtx, INPUT_VALUE-1), np.matrix.transpose(initData)))[9, 0]&(2**64-1))