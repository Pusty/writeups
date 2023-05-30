import os
import angr
import pyvex
import claripy
import angr.analyses.bindiff
import time

# opcodes (as in (a)) and location in binary '0' as reference
refFuncSet = {
    (0xD, 0x99d0),
    (0xE, 0x6f30),
    (0xF, 0x73d0),
    (0x10, 0x8470),
    (0x11, 0x7860),
#    (0x12, 0x7fe0), # same as 0xf for some reason
    (0x14, 0x9970),
    (0x15, 0x8de0),
    (0x16, 0x90c0),
    (0x17, 0x93a0),
    (0x1b, 0x9690),
    (0x1f, 0x8da0),
    (0x22, 0x8900),
#    (0x28, 0x9e80), # special case matching for these (they read /dev/urandom)
#    (0x29, 0x9f70),
#    (0x2a, 0xa070)
}

refFuncs = []
# use binary '0' as a reference for finding the opcode handlers
refProj = angr.Project("output/0", auto_load_libs=False, main_opts={'base_addr': 0})


for (opcode, addr) in refFuncSet:
    cfg = refProj.analyses.CFGEmulated(starts=[addr], call_depth=1, keep_state=True)
    f = cfg.kb.functions[addr]
    refFuncs.append((opcode, f))
print("Reference Table Build...")

# get the address of "main" from _start 
def get_main(p):
    data_ptr = 0
    for stmt in p.factory.block(p.entry).vex.statements:
        if isinstance(stmt, pyvex.IRStmt.Put):
            if stmt.offset == 72: # rdi
                data_ptr = stmt.data.con.value
    
    return data_ptr

# get the vm program buffer, length and address of the next function
def get_buffer(p, main):
    data_len = 0
    data_ptr = 0
    for stmt in p.factory.block(main).vex.statements:
        if isinstance(stmt, pyvex.IRStmt.Put):
            if stmt.offset == 64: # esi
                data_len = stmt.data.con.value
            if stmt.offset == 72: #rdi
                data_ptr = stmt.data.con.value
        
    nextFunc = p.factory.block(main).vex.next.con.value
    return (nextFunc, data_ptr, data_len)

# get the vm loop (skipping past the "Passphrase" method if it exists)
def get_vmbody(p, password):
    cfg = p.analyses.CFGEmulated(starts=[password], call_depth=1, keep_state=True)
    f = cfg.kb.functions[password]
    
    putsexits = False
    for called in f.functions_called():
        if called.name == "puts": 
            putsexits = True
            break
   
    vmbodywrapper = password # this is true for binary "0"
    if putsexits:
        for called in f.functions_called():
            if not called.is_default_name: continue
            if p.factory.block(called.addr).vex.jumpkind == "Ijk_Boring": continue # this is the TEA decrypt
            vmbodywrapper = called.addr
            break
    
    cfg = p.analyses.CFGEmulated(starts=[vmbodywrapper], call_depth=1, keep_state=True)
    f = cfg.kb.functions[vmbodywrapper]
    vmbody = 0
    for called in f.functions_called():
        if not called.is_default_name: continue
        vmbody = called.addr
        break
            
    return vmbody
    
# get the actual vm opcode dispatcher
def get_dispatcher(p, vmbody):
    cfg = p.analyses.CFGEmulated(starts=[vmbody], call_depth=3, keep_state=True)
    f = cfg.kb.functions[vmbody]
    
    dispatcher = 0
    for called in f.functions_called():
        if len(called.block_addrs) > 4: # all others are 0 or 1
            dispatcher = called.addr
    
    assert dispatcher != 0, "[Dispatcher] Dispatcher not found?"
    return dispatcher
    
# Use angr.analyses.bindiff.FunctionDiff to try to figure out which opcode this function represents
def profile_function(p, f):
    cfg = p.analyses.CFGEmulated(starts=[f.addr], call_depth=1, keep_state=True)
    f = cfg.kb.functions[f.addr]
    matches = []
    
    
    for called in f.functions_called():
        if called.name == "fopen":
            matches = [0x28]
            break
    if len(matches) == 0:
        # could optimize this by making it less safe (diff only with not yet found ones)
        for (opcode, func) in refFuncs:   
            if angr.analyses.bindiff.FunctionDiff(func, f).probably_identical:
                matches.append(opcode)
        
    assert len(matches) != 0, "[VM Profiling] No match found"
    assert len(matches) == 1, "[VM Profiling] Too many matches found "+str(matches)
    return matches[0]
    
# given the dispatcher and opcode handler, figure out which opcode needs to be given so the handler is called
def profile_path(p, fromFunc, toFunc, otherFuncs):
    opcodeVar = claripy.BVS('opcode', 16)
    stackStruct = angr.PointerWrapper(opcodeVar)
    vmStruct    = angr.PointerWrapper(b'\0'*0xb0)
    start_state = p.factory.call_state(fromFunc, vmStruct, stackStruct , add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    simgr = p.factory.simulation_manager(start_state)
    explored = simgr.explore(find=toFunc, avoid=otherFuncs, step_func=lambda lsm: lsm.drop(stash='avoid'))
    assert len(explored.found) != 0, "[VM Path] No solution found"
    assert len(explored.found) == 1, "[VM Path] Too many paths found "+str(explored.found)
    solution = explored.found[0].solver.eval(opcodeVar)
    solution = ((solution >> 8)&0xff) | ((solution&0xff)<<8)
    return solution
    
# iterate the opcode handlers of the dispatcher and map the new opcodes to the '0' binary mapping
def profile_vm_dispatcher(p, dispatcher):
    cfg = p.analyses.CFGEmulated(starts=[dispatcher], call_depth=1, keep_state=True)
    f = cfg.kb.functions[dispatcher]
    
    matches = set()
    called_functions = f.functions_called()
    pathMap = {}
    for called in called_functions:
        match = profile_function(p, called)
        matches.add(match)
        path = profile_path(p, f.addr, called.addr, [c.addr for c in called_functions if c.addr != called.addr])
        pathMap[path] = match
    assert len(matches) == 13, "[VM Dispatcher] Something isn't quite right"
    return pathMap
    
    
arr = os.listdir('output')

# skip (a) binaries 
#arr = [a for a in arr if len(a) < 5]

def run(f):
    start = time.time()

    print("Loading file "+f)
    p = angr.Project("output/"+f, auto_load_libs=False, main_opts={'base_addr': 0})


    main_addr = get_main(p)
    print(hex(main_addr))

    password_addr, data_ptr, data_len = get_buffer(p, main_addr)
    print(hex(password_addr), hex(data_ptr), hex(data_len))

    vmbody_addr = get_vmbody(p, password_addr)
    print(hex(vmbody_addr))

    dispatcher_addr = get_dispatcher(p, vmbody_addr)
    print(hex(dispatcher_addr))

    mapping = profile_vm_dispatcher(p, dispatcher_addr)
    print(mapping)

    end = time.time()
    print(end - start, "Time elapsed")

f = arr[1] # select binary to try 
run(f)