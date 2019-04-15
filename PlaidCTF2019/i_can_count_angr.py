import angr
import claripy

# load the binary  without dependencies
p = angr.Project("i_can_count_8484ceff57cb99e3bdb3017f8c8a2467", auto_load_libs=False)

# calculate all the addresses as they depend on the loading address
CHECK_FLAG_ADDR = p.loader.find_symbol('check_flag').rebased_addr
FLAG_BUF_ADDR = p.loader.find_symbol('flag_buf').rebased_addr

PRINT_FLAG_ADDR = p.loader.main_object.mapped_base + 0x0000f87
WRONG_FLAG_ADDR = p.loader.main_object.mapped_base + 0x0000fae

# create a state at the beginning of the check_flag function
st = p.factory.blank_state(addr=CHECK_FLAG_ADDR)

# create solvable variables for the flag characters
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(0x13)]
flag = claripy.Concat(*flag_chars)

# flag characters can only be digits
for k in flag_chars:
    st.solver.add(k >= ord('0'))
    st.solver.add(k <= ord('9'))
    
# make the flag_buf memory depending on user input and solvable
for i in range(len(flag_chars)):
    st.mem[FLAG_BUF_ADDR+i:].byte = flag_chars[i]
    
sm = p.factory.simulation_manager(st)


print("Calculating Flag")

# try to find a solution that prints out the flag and does not return before
sm.explore(find=PRINT_FLAG_ADDR,avoid=WRONG_FLAG_ADDR)

# print out the simulation managers state
print(sm)

# use the found solution to evaluate the flag characters to the wanted flag
found_state = sm.found[0].state
print("PCTF{%s}" % (found_state.solver.eval(flag, cast_to=str)))
