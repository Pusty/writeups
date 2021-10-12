import os
import pyverilator
import random

# setup build directory and cd to it
build_dir = os.path.join(os.path.dirname(__file__), 'build', os.path.basename(__file__))
os.makedirs(build_dir, exist_ok = True)
os.chdir(build_dir)

with open('chal.v', 'w') as out:
    with open('../../chal.v', 'r') as f:
            out.write(f.read())

sim = pyverilator.PyVerilator.build('chal.v')


#sim.start_vcd_trace('chal.vcd')

#sim.start_gtkwave()
#sim.send_to_gtkwave(sim.io)
#sim.send_to_gtkwave(sim.internals)

def tick_clock(datamap=None):
    sim.io.G_HPBX0000 = 0 # CLK = 0
    sim.io.G_HPBX0000 = 1 # CLK = 1
    
def setdata(v):
    sim.io.MIB_R0C40_PIOT0_JPADDIB_PIO = v # TX = v

def readdata():
    return sim.io.MIB_R0C40_PIOT0_PADDOA_PIO # RX
    
def writebyte(d):
    # LOW for one UART tick to indicate sending
    setdata(0)
    for waitfor in range(CLOCK_RATE):
        tick_clock()
    # Send data bit for bit
    for b in range(8):
        setdata((d >> b) & 1)
        for waitfor in range(CLOCK_RATE):
            tick_clock()
    # HIGH for two UART ticks to process data
    setdata(1)
    for waitfor in range(CLOCK_RATE):
        tick_clock()

    
def readbyte():
    c = 0
    # receive data bit for bit
    for x in range(8):
        for waitfor in range(CLOCK_RATE):
            tick_clock()
        c = (readdata()<<x) | c
    return c
    
CLOCK_RATE = 100 # as description says, 100 clock ticks per symbol

# reset
setdata(1)
sim.io.MIB_R0C60_PIOT0_JPADDIA_PIO = 0
for waitfor in range(CLOCK_RATE):
    tick_clock()
sim.io.MIB_R0C60_PIOT0_JPADDIA_PIO = 1

while True:
    texttosend = input("< ")
    if texttosend == "": texttosend = "\x00"
    for chartosend in texttosend:
        writebyte(ord(chartosend))
        datareceived = readbyte()
        print("> "+chr(datareceived))
    
#sim.stop_gtkwave()
#sim.stop_vcd_trace()