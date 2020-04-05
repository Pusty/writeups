# uncompyle6 version 3.2.3
# Python bytecode 3.6 (3379)
# Decompiled from: Python 2.7.10 (default, May 23 2015, 09:44:00) [MSC v.1500 64 bit (AMD64)]
# Embedded file name: pybonhash.py
# Compiled at: 2020-03-28 14:11:38
# Size of source mod 2**32: 1017 bytes
import string, sys, hashlib, binascii
from Crypto.Cipher import AES
from flag import key
if not len(key) == 42:
    raise AssertionError
data = open(sys.argv[1], 'rb').read()
if not len(data) >= 191:
    raise AssertionError
FIBOFFSET = 4919
MAXFIBSIZE = len(key) + len(data) + FIBOFFSET

def fibseq(n):
    out = [
     0, 1]
    for i in range(2, n):
        out += [out[i - 1] + out[i - 2]]

    return out


FIB = fibseq(MAXFIBSIZE)
i = 0
output = ''
while i < len(data):
    data1 = data[FIB[i] % len(data)]
    key1 = key[(i + FIB[FIBOFFSET + i]) % len(key)]
    i += 1
    data2 = data[FIB[i] % len(data)]
    key2 = key[(i + FIB[FIBOFFSET + i]) % len(key)]
    i += 1
    tohash = bytes([data1, data2])
    toencrypt = hashlib.md5(tohash).hexdigest()
    thiskey = bytes([key1, key2]) * 16
    cipher = AES.new(thiskey, AES.MODE_ECB)
    enc = cipher.encrypt(toencrypt)
    output += binascii.hexlify(enc).decode('ascii')

print(output)
# okay decompiling pybonhash.cpython-36.pyc
