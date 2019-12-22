import angr
import claripy

p = angr.Project("change_my_mind")

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(0x30-1)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])
    
state = p.factory.entry_state(stdin=flag)
simgr = p.factory.simulation_manager(state)

print(simgr.explore(find=(0x400000+0x169d), avoid=(0x400000+0x160A)))
f = simgr.found[0] # this just confirms that the character length is correct (0x2F characters)
simgr.move('found', 'active') 
print(simgr.explore(find=(0x400000+0x1693), avoid=(0x400000+0x160A)))
f = simgr.found[0] # this is the state passing a check of some calculate on input == 0
print(f)
print((b"STDOUT: "+f.posix.dumps(1)).decode("utf-8"))
print((b"FLAG: "+f.solver.eval(flag, cast_to=bytes)).decode("utf-8"))

"""
STDOUT: Hello!
Please provide your credentials!
>>Lets'check...

FLAG: justCTF{1_ch4ng3d_my_m1nd_by_cl34r1n6_7h3_r00m}
"""