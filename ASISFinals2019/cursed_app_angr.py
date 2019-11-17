import angr
import claripy

def main():
    print("Loading..")
    p = angr.Project("cursed_app.elf", load_options={'auto_load_libs': False})
    # provide the argument to the fake file
    state = p.factory.entry_state(args= ["cursed_app.elf", "tmpLicence"])

    license_name = "tmpLicence"

    bytestring = None
    line = []
    for i in range(0x3b):
        line.append(state.solver.BVS('tmpLicence_%d' % (i), 8))
        
    bytestring = claripy.Concat(*line)
    
    # only allow printable characters
    for byte in bytestring.chop(8):
        state.add_constraints(byte >= '\x20') # ' '
        state.add_constraints(byte <= '\x7e') # '~'

    license_file = angr.storage.file.SimFile(license_name, bytestring) # create symbolic file with content basesd on symbolic string
    state.fs.insert(license_name, license_file) # insert the file into the state

    # offsets to the next blocks, and "win" condition
    blocks = [0x1177, 0x11be, 0x11f6 , 0x1231, 0x1269, 0x12a3, 0x12d6, 0x1312, 0x1351, 0x138c, 0x13ca, 0x140d, 0x1445, 0x1481, 0x14c2, 0x14fb, 0x1536, 0x1572, 0x15b3
    , 0x15ee, 0x1629, 0x166a, 0x16a6, 0x16df, 0x1715, 0x1750, 0x178c, 0x17c7, 0x1805, 0x1843, 0x187b, 0x18c1, 0x18fd, 0x193b, 0x1977, 0x19b3, 0x19f2, 0x1a2b
    , 0x1a66, 0x1a9c, 0x1ad7, 0x1b17, 0x1b52, 0x1b91, 0x1bcd, 0x1c05, 0x1c3e, 0x1c7c, 0x1cba, 0x1cf3, 0x1d2e, 0x1d6f, 0x1daa, 0x1de0, 0x1e19, 0x1e54, 0x1e90
    , 0x1ece, 0x1f06, 0x1f3b]
    
    # create simulation
    simgr = p.factory.simulation_manager(state)

    # explore the paths and continue from the one that worked
    for i in range(len(blocks)):
        simgr.explore(
                find=(0x400000 + blocks[i]),
                avoid=(0x400000  + 0x1f4f)
            )
        print(simgr)
        found = simgr.found[0]
        simgr.move('found', 'active') # add the path that reached the next block to the one we continue from
        print("Found for "+str(i+1)+" characters.")
    data, actual_size, new_pos = license_file.read(0, 0x40) # read the symbolic file
    print(found.solver.eval(bytestring, cast_to=bytes)) # and output
        
    # ASIS{y0u_c4N_s33_7h15_15_34R13R_7h4n_Y0u_7h1nk_r16h7?__!!!}
    # correct one is ASIS{y0u_c4N_s33_7h15_15_34513R_7h4n_Y0u_7h1nk_r16h7?__!!!}  ('5' instead of 'R' in "easier")
    return

if __name__ == '__main__':
    main()
