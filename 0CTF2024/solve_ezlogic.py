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