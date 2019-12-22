import angr
import claripy

p = angr.Project("change_my_mind")

symsize = claripy.BVS('inputLength', 64)
simfile = angr.SimFile('/tmp/stdin',size=symsize)

state = p.factory.entry_state(stdin=simfile)
simgr = p.factory.simulation_manager(state)

simgr.explore(find=lambda s: b"Good" in s.posix.dumps(1))
f = simgr.found[0]
print(f)
print((b"STDOUT: "+f.posix.dumps(1)).decode())
print((b"FLAG: "+f.posix.dumps(0)).decode())

"""
STDOUT: Hello!
Please provide your credentials!
>>Lets'check...
Good password. Congratulations!

FLAG: justCTF{1_ch4ng3d_my_m1nd_by_cl34r1n6_7h3_r00m}
"""