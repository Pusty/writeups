f = open("fsmir.sv")
lines = f.read().split("\n")

entries = {}
for line in lines:
    if not "(di ^ c)" in line: continue
    line = line.strip()
    cond   = int(line.split(":")[0].split("'b")[1],2)
    check  = int(line.split("==")[1].split(")")[0].split("'b")[1],2)
    result = int(line.split("<=")[1].split(";")[0].split("'b")[1],2)
    entries[cond] = (result, chr(check^cond))

state = 0
flag = []

while state != 59:
    state, flag_part = entries[state]
    flag.append(flag_part)
    
print(''.join(flag)) # justCTF{SystemVerilog_is_just_C_with_fancy_notation_right?}