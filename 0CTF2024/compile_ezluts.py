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
