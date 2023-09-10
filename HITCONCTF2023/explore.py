from z3 import *


# parse subleq commands
f = open("chal.txt", "r")
content = f.read()
f.close()
lines = content.split("\n")
tokens = []
for line in lines:
    tokens += line.split(" ")
tokens.remove("")

# turn tokens into integers
for i in range(len(tokens)):
    tokens[i] = int(tokens[i])

# convert to signed 64 bit value
def toSigned64(n):
    n = n & 0xffffffffffffffff
    return n | (-(n & 0x8000000000000000))

# simplify and make concrete if possible
def simple(mem, addr):
    if not isinstance(mem[addr], int):
        s = simplify(mem[addr])
        if isinstance(s, z3.z3.IntNumRef):
            mem[addr] = toSigned64(s.as_long())
        if isinstance(s, z3.z3.BitVecNumRef):
            mem[addr] = toSigned64(s.as_long())
        else:
            mem[addr] = s
            
            
inp = 'y~ ~#1A~' #"A"*8 # dummy input
inpIndex = 0 # index of faked stdin
variables = [] # symbolic variables
variableConstraints = [] # constrains on flag characters to solve with
solver = Solver() # solver used to explore

# check if term contains "x + constant"
# useful for identifying symbolic comparison against constants
def containsConstant(term):
    c = term.children()
    if len(c) == 0:
        return False
    elif str(term.decl()) == "+" or str(term.decl()) == "-":
        for e in c:
            if isinstance(e, z3.z3.IntNumRef):
                return True
            if isinstance(e, z3.z3.BitVecNumRef):
                return True
            elif containsConstant(e):
                return True
        return False
    else:
        for e in c:
            if containsConstant(e):
                return True
        return False

# Read fake STDIN
def readInput():
    global inpIndex
    
    if inpIndex == len(inp):
        v = 0xA
    else:
        # make input symbolic
        v = BitVec("input["+str(inpIndex)+"]", 64)
        # actual variable constraints
        variableConstraints.append(And(v >= 0x20, v < 0x7f))
        variables.append(v)
        inpIndex += 1
    return -v # this is how it is implemented in the binary
    
# Initialize program counter and memory
pc = 0
mem = tokens+[0 for i in range(0x80000-len(tokens))]

# While pc is not negative, run
while pc >= 0:
    #print(pc,":", mem[pc], mem[pc+1], mem[pc+2])
    
    # simplify, specifically - try to make concrete if possible
    simple(mem, pc)
    simple(mem, pc+1)
    simple(mem, pc+2)
    
    # Read from STDIN (faked)
    if mem[pc] < 0:
        a = readInput()
        print(pc, "INPUT", a)
    else:
        # simplify, specifically - try to make concrete if possible
        simple(mem, mem[pc])
        a = mem[mem[pc]]
    
    # Print to STDOUT
    if mem[pc+1] < 0:
        if not isinstance(a, int): 
            print(pc, "PRINT", a)
        elif a > 0:
            print(pc, "PRINT", chr(a))
    else:
        # simplify, specifically - try to make concrete if possible
        simple(mem, mem[pc+1])
        addr = mem[pc+1]
        mem[addr] = mem[addr] - a
        simple(mem, addr)

    # simplify, specifically - try to make concrete if possible
    simple(mem, mem[pc+1])
    
    # this means this memory value is symbolic
    if not isinstance(mem[mem[pc+1]], int):
    
        term = mem[mem[pc+1]]
    
        # concrete path for dummy / wrong input
        
        termConcrete = term
        for i in range(len(variables)):
            termConcrete = substitute(termConcrete, (variables[i], BitVecVal(ord(inp[i]), 64)))
        termConcrete = simplify(termConcrete > 0)
        if not isinstance(termConcrete, z3.z3.BoolRef):
            print("Couldn't make concrete ", term, "to",termConcrete)
            break
            
        if pc+3 != mem[pc+2]:  # branch != next instruction
            solver.reset()
            solver.add(variableConstraints)
            solver.add(term == 0)
            canBeSat = solver.check()
            if canBeSat == sat: # can eval to 0 / equal
                m = solver.model()
                solver.reset()
                solver.add(variableConstraints)
                solver.add(term != 0)
                canBeUnsat = solver.check()
                if canBeUnsat == sat: # can also not take this branch
                    if containsConstant(term): # check the term constains a constant addition or substraction
                        print("PC[",pc,"]:", "(", mem[pc], mem[pc+1], mem[pc+2], ")", ":", term, "#", "Possible Solution:", bytes([m[variables[i]].as_long() for i in range(len(variables))]), flush=True)
   
        # if term > 0
        if termConcrete:
            pc = pc + 3
        # if term <= 0
        else:
            pc = mem[pc+2]
            
    # this means this memory value is concrete
    elif mem[mem[pc+1]] > 0:
        pc = pc + 3
    else:
        pc = mem[pc+2]