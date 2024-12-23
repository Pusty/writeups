# EzLogic

EzLogic is a Verilog challenge implemented on an FPGA. We are given processed HDL code and behavior models for the FPGA it was made for.

## Solution

The challenge takes one byte per cycle as input and gives out one byte of output.
We are given 42 bytes of output we need to provide the input for.

This is easily solvable by bruteforcing the next byte sequentially:


```python
import os
import pyverilator


build_dir = os.path.join(os.path.dirname(__file__), 'build', os.path.basename(__file__))
os.makedirs(build_dir, exist_ok = True)
os.chdir(build_dir)

with open('EzLogic_top_synth.v', 'w') as out:
    with open('../../problem/EzLogic_top_synth.v', 'r') as f:
            out.write(f.read())
            
for behavior in ["GND", "VCC", "BUFG", "IBUF", "OBUF", "LUT2", "LUT1", "FDCE", "CARRY4"]:
    with open(f'{behavior}.v', 'w') as out:
        with open(f'../../behavioral models/{behavior}.v', 'r') as f:
                out.write(f.read())
               
sim = pyverilator.PyVerilator.build('EzLogic_top_synth.v')

def try_input(flag_input, match_output):
    # reset
    sim.io.rst_n = 0
    sim.io.rst_n = 1
    flag_out = []
    
    for i in range(len(flag_input)):
        sim.io.data_in = flag_input[i]
        sim.io.valid_in = 1
        
        # clock cycle
        sim.io.clk = 0
        sim.io.clk = 1
        
        if sim.io.valid_out == 1:
            flag_out.append(int(sim.io.data_out))
            if match_output[i] != flag_out[i]: return i

    sim.io.valid_in = 0
    sim.io.data_in = 0
    return len(flag_input)

input_vec = []
correct_flag = bytes.fromhex("30789d5692f2fe23bb2c5d9e16406653b6cb217c952998ce17b7143788d949952680b4bce4c30a96c753")
for j in range(42):
    for i in range(0xff):
        if(try_input(bytes(input_vec+[i]), correct_flag[:j+1]) == j+1):
            input_vec.append(i)
            break
    print(hex(j), bytes(input_vec))
```

Which at the end gives us

`0x29 b'0ops{aadc337c-b5a0-4ff0-ad94-9d1cf41956f4}`

# EzLUTs

EzLUTs is a Verilog challenge implemented on an FPGA. We are given processed HDL code and behavior models for the FPGA it was made for.

## Solution

This challenge takes 42 bytes as input at once and only gives out and output of correct/incorrect as one bit.

Given the entire HDL code almost entirely consists out of Look Up Tables and synthesizing those to code made weird (inefficient) shift patterns out of it, my first step was optimizing the code:

```python
import re

f = open("EzLUTs_top_synth.v", "r")
text = f.read()
f.close()

regex = r"LUT6 #\(\s*\.INIT\(64'h6996966996696996\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = (\1 ^ \2 ^ \3 ^ \4 ^ \5 ^ \6);"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0000001000000000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((~\1) & (~\2) & \3 & (~\4) & (~\5) & \6);"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h8000000000000000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = (\1 & \2 & \3 & \4 & \5 & \6);"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0000000096696996\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((\1 ^ \2 ^ \3 ^ \4 ^ \5) & (~\6));"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h9669000000009669\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((~(\5 ^ \6))&(~(\1 ^ \2 ^ \3 ^ \4)));"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0000000100000000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((~\1) & (~\2) & (~\3) & (~\4) & (~\5) & \6);"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h6996000000006996\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((~(\5 ^ \6))&((\1 ^ \2 ^ \3 ^ \4)));"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0069690069000069\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((~(\4 ^ \5 ^ \6))&(~(\1 ^ \2 ^ \3)));"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0000000000000010\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((~\1) & (~\2) & \3 & (~\4) & (~\5) & (~\6));"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0096960096000096\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((~(\4 ^ \5 ^ \6))&((\1 ^ \2 ^ \3)));"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h9669699600000000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((\1 ^ \2 ^ \3 ^ \4 ^ \5) & (\6));"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0000000069969669\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((~(\1 ^ \2 ^ \3 ^ \4 ^ \5)) & (~\6));"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h9600009600969600\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((\4 ^ \5 ^ \6)&(\1 ^ \2 ^ \3));"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0008000000000000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((\1) & (\2) & (~\3) & (~\4) & (\5) & (\6));"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0000699669960000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = (((\5 ^ \6))&((\1 ^ \2 ^ \3 ^ \4)));"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h1000000000000000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ( (~\1) & (~\2) & \3 & \4 & \5 & \6 );"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0000000000000800\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ( \1 & \2 & (~\3) & \4 & (~\5) & (~\6) );"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0000000000000002\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ( \1 & (~\2) & (~\3) & (~\4) & (~\5) & (~\6) );"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0000000000000020\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ( \1 & (~\2) & \3 & (~\4) & (~\5) & (~\6) );"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0000000800000000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ( \1 & \2 & (~\3) & (~\4) & (~\5) & \6 );"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0000008000000000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ( \1 & \2 & \3 & (~\4) & (~\5) & \6 );"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0800000000000000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ( \1 & \2 & (~\3) & \4 & \5 & \6 );"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h6000006000000000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((\1 ^ \2) & \3 & (~(\4 ^ \5)) & \6);"
text = re.sub(regex, replaceText, text)

regex = r"LUT6 #\(\s*\.INIT\(64'h0000000000004114\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.I5\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \7 = ((~\1) & (\2^\3^\4) & (~\5) & (~\6));"
text = re.sub(regex, replaceText, text)

regex = r"LUT2 #\(\s*\.INIT\(4'h6\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \3 = (\1 ^ \2);"
text = re.sub(regex, replaceText, text)

regex = r"LUT3 #\(\s*\.INIT\(8'h96\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \4 = (\1 ^ \2 ^ \3);"
text = re.sub(regex, replaceText, text)

regex = r"LUT4 #\(\s*\.INIT\(16'h6996\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \5 = (\1 ^ \2 ^ \3 ^ \4);"
text = re.sub(regex, replaceText, text)

regex = r"LUT5 #\(\s*\.INIT\(32'h96696996\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \6 = (\1 ^ \2 ^ \3 ^ \4 ^ \5);"
text = re.sub(regex, replaceText, text)

regex = r"LUT5 #\(\s*\.INIT\(32'h20000000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \6 = ( \1 & (~\2) & \3 & \4 & \5 );"
text = re.sub(regex, replaceText, text)

regex = r"LUT5 #\(\s*\.INIT\(32'h08000000\)\)\s*[^\s]+\s*\(\.I0\(([^\)]+)\),\s*\.I1\(([^\)]+)\),\s*\.I2\(([^\)]+)\),\s*\.I3\(([^\)]+)\),\s*\.I4\(([^\)]+)\),\s*\.O\(([^\)]+)\)\);"
replaceText = r"assign \6 = ( \1 & \2 & (~\3) & \4 & \5 );"
text = re.sub(regex, replaceText, text)

# Change bit endianess of input buffer
text = text.replace("[0:335]", "[335:0]")

regex = r"\(\* SOFT_HLUTNM [^\)]+\)\s*"
replaceText = r""
text = re.sub(regex, replaceText, text)


f = open("EzLUTs_top_synth_mod.v", "w")
f.write(text)
f.close()
```

Then based on that I compiled it to C++ using verilator

```python
import os
import pyverilator
import random

# setup build directory and cd to it
build_dir = os.path.join(os.path.dirname(__file__), 'build', os.path.basename(__file__))
os.makedirs(build_dir, exist_ok = True)
os.chdir(build_dir)

with open('EzLUTs_top_synth.v', 'w') as out:
    with open('../../EzLUTs_top_synth_mod.v', 'r') as f:
            out.write(f.read())
            
for behavior in ["GND", "VCC", "BUFG", "IBUF", "OBUF", "LUT2", "LUT1", "LUT3", "LUT4", "LUT5", "LUT6", "FDCE", "CARRY4"]:
    with open(f'{behavior}.v', 'w') as out:
        with open(f'../../../EzLogic/behavioral models/{behavior}.v', 'r') as f:
                out.write(f.read())
               
sim = pyverilator.PyVerilator.build('EzLUTs_top_synth.v')
```

The compiled `VEzLUTs_top_synth.cpp` file contains the function `VEzLUTs_top_synth::_combo__TOP__1` which is the C++ version of the code.

My next step was to reformat this and turn it into python code:

```python
from z3 import *

def _combo__TOP__1(data0, data1, data2, data3, data4,
data5, data6, data7, data8, data9,
data10
):
    ...
    return simplify(success)


# Make input out individual bits
data_bits = [BitVec(f"data_{i}", 1) for i in range(32*11)]
data = [Concat([data_bits[i*32+j] if (i*32+j < 32*11) else BitVecVal(0, 1)  for j in range(32)][::-1]) for i in range(11)]

# Turn Arithmetic Shifts Right to Logical Shifts Right
BitVecRef.__rshift__ = lambda a, b: LShR(a, b)

success = _combo__TOP__1(*data)

solver = Solver()

# Add additional constrains on the input to speed up solving
# 0ops{ 30 6f 70 73 7b
solver.add(Concat(data_bits[0:8]) == BitVecVal(0x30, 8))
solver.add(Concat(data_bits[8:16]) == BitVecVal(0x6f, 8))
solver.add(Concat(data_bits[16:24]) == BitVecVal(0x70, 8))
solver.add(Concat(data_bits[24:32]) == BitVecVal(0x73, 8))
solver.add(Concat(data_bits[24:32]) == BitVecVal(0x73, 8))
solver.add(Concat(data_bits[32:40]) == BitVecVal(0x7b, 8))

solver.add(success != 0)
print(solver.check())
m = solver.model()
print(m)

bitmap = {}
for i in range(42*8):
    bitmap[i] = (m[data_bits[i]].as_long())

# Turn bits back into characters
flag = ''
for j in range(42):
    v = 0
    for i in range(8):
        v = (v << 1) | bitmap[j*8+i]
    flag += (chr(v))
    
print(flag)
```

This takes about one hour to solve for the flag `0ops{ce5cff29-4d78-4c72-ace3-e4f9405dda30}`