f = open("fsmir2.sv")
lines = f.read().split("\n")

entries = {}

for line in lines:
    line = line.strip()
    if "case(di)" in line:
        last_cond = int(line.split(" : ")[0].split("'b")[1], 2)
    elif "default: c <= 9'b0;" in line: pass
    elif ": c <= " in line:
        check_di  = int(line.split(": c <=")[0].split("'b")[1], 2)
        new_value = int(line.split("9'b")[1].split(";")[0], 2)
        if not new_value in entries:
            entries[new_value] = []
        entries[new_value].append((last_cond, check_di))
        
last_value = int("101001101", 2)
before = last_value
flag = []

while before != 0:
    l = entries[before]
    if len(l) > 1:
        print before
        print entries[before]
        exit(0)
    before, flag_part = l[0]
    flag.append(chr(flag_part))
    
flag.reverse()
print(''.join(flag)) # justCTF{I_h0p3_y0u_us3d_v3r1L4t0r_0r_sth...}