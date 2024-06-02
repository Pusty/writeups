import subprocess

# from output.txt (input r0, r1), (output r0, r1)
output_txt = [
((0xD5DB2C94, 0x959DB87D), (0x57D21D0, 0x7163E0F5)),
((0xE1D9AB69, 0x7F920AC7), (0x2D47D458, 0xD18F4E13)),
((0x740C6CD5, 0xCADCA511), (0xE83B0109, 0x273B255C)),
((0x9147A5EF, 0x24C49DD1), (0x7AE86AFE, 0x3ECB6289)),
((0xADE26435, 0xEB531A28), (0x124C8D25, 0x73C81102)),
((0x343E0B03, 0xB5D7D555), (0xA4FC371C, 0x80C87931)),
((0x237CD1E, 0xCA65A03E), (0x9CEBAD55, 0x8F743074)),
((0xE9B3362E, 0xA551DBED), (0x1C899FBB, 0xF9404F51))]

# use translated binary as oracle with chosen a,b,c,d
def oracle(a, b, i):
    args = ["./vm_translated_simplified", str(a), str(b), str(i&0xffffffff), str((i>>32)&0xffffffff)]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    output = stdout.strip().decode("ascii")
    return ZZ(output)

# turn 64-bit integer into 64-bit entry GF(2) vector
def vec64(val):
    lst = val.digits(base=2)
    return vector(GF(2), lst+[0]*(64-len(lst)))

flag = b''
for cur_entry in output_txt:
    a, b = cur_entry[0]
    out_a, out_b = cur_entry[1]

    # result of actual encryption
    wanted = vec64((out_b<<32) | out_a)
    
    # oracle for (0,0)
    base = vec64(oracle(a, b, 0))

    # Build Matrix for all the indiviual bits
    A = Matrix(GF(2), [vec64(oracle(a, b, 1<<i))+base for i in range(64)]).transpose()
    # Solve A sol = wanted
    sol = A.solve_right(wanted-base)
    # Convert solution to bytes
    flag += (int(ZZ(list(sol), base=2)).to_bytes(8, 'big'))

# codegate2024{B45IC_i5_n07_d34d_4nd_n3v3r_wi11_b3_2024_MQCJAb4Wr}
print(flag)