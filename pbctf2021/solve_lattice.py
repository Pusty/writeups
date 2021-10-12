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

CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_{}\x00"

PW_STRING = "" # v3ril0g_1s_pain_peko
PW_FOUND = False

FLAG_STR = ""
FLAG_FOUND = False

while not FLAG_FOUND:
    for j in range(len(CHARSET)):

        # reset simulation fully - not needed
        #sim.model = sim.lib.construct()
        #sim._sim_init()
        
        # set RX high as default
        setdata(1)
        
        datatosend = ord(CHARSET[j])
        # RESET
        sim.io.MIB_R0C60_PIOT0_JPADDIA_PIO = 0
        for waitfor in range(CLOCK_RATE):
            tick_clock()
        sim.io.MIB_R0C60_PIOT0_JPADDIA_PIO = 1
        
        
        # write 'g' first
        for c in PW_STRING:
            writebyte(ord(c))
        
        writebyte(datatosend)
        datareceived = readbyte()
        
        # red block = output buffer
        redBlock = 0
        redBlock = redBlock | (sim.internals["R3C38_PLC2_inst.sliceC_inst.ff_1.Q"]<<0)
        redBlock = redBlock | (sim.internals["R5C38_PLC2_inst.sliceA_inst.ff_1.Q"]<<1)
        redBlock = redBlock | (sim.internals["R3C38_PLC2_inst.sliceB_inst.ff_0.Q"]<<2)
        redBlock = redBlock | (sim.internals["R3C40_PLC2_inst.sliceA_inst.ff_0.Q"]<<3)
        redBlock = redBlock | (sim.internals["R3C38_PLC2_inst.sliceD_inst.ff_0.Q"]<<4)
        redBlock = redBlock | (sim.internals["R5C38_PLC2_inst.sliceB_inst.ff_0.Q"]<<5) 
        redBlock = redBlock | (sim.internals["R3C38_PLC2_inst.sliceA_inst.ff_0.Q"]<<6) 
        redBlock = redBlock | (sim.internals["R3C40_PLC2_inst.sliceD_inst.ff_0.Q"]<<7)
        
        # yellow block = normal output / echo
        yellowBlock = 0
        yellowBlock = yellowBlock | (sim.internals["R2C39_PLC2_inst.sliceD_inst.ff_0.Q"]<<0)
        yellowBlock = yellowBlock | (sim.internals["R5C40_PLC2_inst.sliceD_inst.ff_0.Q"]<<1)
        yellowBlock = yellowBlock | (sim.internals["R2C40_PLC2_inst.sliceB_inst.ff_0.Q"]<<2)
        yellowBlock = yellowBlock | (sim.internals["R2C42_PLC2_inst.sliceB_inst.ff_0.Q"]<<3)
        yellowBlock = yellowBlock | (sim.internals["R4C39_PLC2_inst.sliceC_inst.ff_0.Q"]<<4)
        yellowBlock = yellowBlock | (sim.internals["R6C39_PLC2_inst.sliceD_inst.ff_0.Q"]<<5)
        yellowBlock = yellowBlock | (sim.internals["R4C40_PLC2_inst.sliceD_inst.ff_0.Q"]<<6)
        yellowBlock = yellowBlock | (sim.internals["R5C39_PLC2_inst.sliceD_inst.ff_0.Q"]<<7)
        
        # interesting comparison results
        blueBlock = 0
        blueBlock = blueBlock | (sim.internals["R3C41_PLC2_inst.sliceB_inst.ff_1.Q"]<<0)
        blueBlock = blueBlock | (sim.internals["R4C43_PLC2_inst.sliceC_inst.ff_0.Q"]<<1)
        blueBlock = blueBlock | (sim.internals["R4C41_PLC2_inst.sliceC_inst.ff_0.Q"]<<2)
        blueBlock = blueBlock | (sim.internals["R6C43_PLC2_inst.sliceA_inst.ff_0.Q"]<<3)
        blueBlock = blueBlock | (sim.internals["R4C42_PLC2_inst.sliceC_inst.ff_0.Q"]<<4)
        blueBlock = blueBlock | (sim.internals["R3C42_PLC2_inst.sliceB_inst.ff_1.Q"]<<5)
        
        
        # use redblock instead of datareceived because there can be reading errors (misalignment)
        
        # if an input results in a nonzero blueBlock result - it is part of the password
        if(blueBlock != 0 and not PW_FOUND):
            print(hex(datatosend)+" => "+hex(yellowBlock)+" => "+hex(redBlock)+ " | "+chr(datatosend))
            print( ("{0:08b} => {1:08b} | B: {2:08b}").format(datatosend, datareceived, blueBlock) )
            PW_STRING = PW_STRING + chr(datatosend)
            print(">" +PW_STRING)
            if redBlock != 0:
                break
            
        # after the password is entered a 0 is output
        if datatosend != redBlock and redBlock == 0:
            PW_FOUND = True
            
        if PW_FOUND:
            if redBlock != 0:
                FLAG_STR = FLAG_STR + chr(redBlock)
            print(">" +FLAG_STR)
            if redBlock == ord('}'):
                FLAG_FOUND = True
            PW_STRING = PW_STRING + "a" # filler
            break
            

print("Done...")

setdata(1)
for waitfor in range(CLOCK_RATE*20):
    tick_clock()


#sim.stop_gtkwave()
#sim.stop_vcd_trace()