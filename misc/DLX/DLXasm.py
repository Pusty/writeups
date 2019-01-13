"""
    This a very minimalistic DLX implementation meant for testing and executing its assembly.
    I'm no trying to be follow any existing Opcode/Function standart as there are a few and all basically abitrary.
    My implementation doesn't try to emulate the Pipelining and internal states either.

    As a debugging messuremeant I both provide the "not real" instructions HALT and DEBUG #immediate as well
        HALT      - Stop the program immediatly
        DEBUG imm - Used as breakpoints, immediate value used for identification
                    
    Jumping to address 0xFFFF exits the program as well
    Trap will continue execution at the address contained at TrapValue*4
    Code,Data and Memory shares the same place in my implementation and is both fully readable and writeable and also zeroed out by default
    Floating Point Instructions work but are not formally correctly implemented, expecially notable for working with double values and me not implementing their affect on multiple floating point registers
    
    Code execution starts at address 0x8000
"""

import re
import struct


from DLXinst import *


class AssembleContext:
    code   = ""      # The code of this assembler context
    lineNr = ""      # Contains the line Nrs encoded in 4 bytes
    debug = False  # Whether Debug mode is enabled (will contain lineNr's in output)
    


def encode(context, parType, pars, line, lineNr):
    opcode = pars[0].upper()
    if not opcode in Instructions:
        raise ValueError("Not a valid instruction @ ["+str(lineNr)+"] '"+line+"'")
        return False
    inst = Instructions[opcode]
    if inst.parameterScheme != parType:
        raise ValueError("Wrong Parameter Scheme for Opcode @ ["+str(lineNr)+"] '"+line+"'")
        return False
        
    if inst.encodingScheme == ENCODING_R:
        opvalue = inst.opcode
        function = inst.functionValue
        Xs      = 0
        Xc      = 0
        Xd      = 0
        
        if parType == PAR_EMPT: pass
        elif parType == PAR_3R or parType == PAR_3F: # OP Rd,Rs,Rc ; OP Fd,Fs,Fc
            Xd = pars[1]
            Xc = pars[3]
            Xs = pars[2]
        elif parType == PAR_3D: # OP Dd,Ds,Dc
            Xd = pars[1]*2
            Xc = pars[3]*2
            Xs = pars[2]*2
        elif parType == PAR_1RS:# OP Rs
            Xs = pars[1]
        elif parType == PAR_1RD:# OP Rd
            Xd = pars[1]
        elif parType == PAR_2F: # OP Fd, Fs
            Xd = pars[1]
            Xs = pars[2]
        elif parType == PAR_2D: # OP Dd, Ds
            Xd = pars[1]*2
            Xs = pars[2]*2
        elif parType == PAR_RF or parType == PAR_FR: # OP Rd, Fs ; OP Fd, Rs  
            Xd = pars[1]
            Xs = pars[2]
        elif parType == PAR_DF or parType == PAR_DR: # OP Dd, Fs ; OP Dd, Rs
            Xd = pars[1]*2
            Xs = pars[2]
        elif parType == PAR_FD or parType == PAR_RD: # OP Fd, Ds ; OP Rd, Ds
            Xd = pars[1]
            Xs = pars[2]*2
        elif parType == PAR_2FC: # OP Fs, Fc
            Xs = pars[1]
            Xd = pars[2]
        elif parType == PAR_2DC: # OP Ds, Dc
            Xs = pars[1]*2
            Xd = pars[2]*2
        else:
            raise SyntaxError("Illegal Parameter Type for R-Encoding @ ["+str(lineNr)+"] '"+line+"'")
            return False
            
        if Xs > 31 or Xs < 0:
            raise ValueError("Source register out of range ("+str(Xs)+") @ ["+str(lineNr)+"] '"+line+"'")
            return False
            
        if Xd > 31 or Xd < 0:
            raise ValueError("Destination register out of range ("+str(Xd)+") @ ["+str(lineNr)+"] '"+line+"'")
            return False
            
        if Xc > 31 or Xc < 0:
            raise ValueError("Auxiliary register out of range ("+str(Xc)+") @ ["+str(lineNr)+"] '"+line+"'")
            return False 
            
        if function > 0x3ff or function < 0:
            raise ValueError("Function out of range ("+str(function)+") @ ["+str(lineNr)+"] '"+line+"'")
            return False
            
        if opvalue > 0x3f or opvalue < 0:
            raise ValueError("Opcode out of range @ ["+str(lineNr)+"] '"+line+"'")
            return False

        value = ((function&0x3ff)<<21)|((Xd&0x1f)<<16)|((Xc&0x1f)<<11)|((Xs&0x1f)<<6)|(opvalue&0x3f)
        context.code += struct.pack("<I", value)
        context.lineNr += struct.pack("<I", lineNr)
        return True
    elif inst.encodingScheme == ENCODING_I:
        opvalue = inst.opcode
        Xs      = 0
        Xd      = 0
        imm     = 0
        
        if parType == PAR_EMPT: pass
        elif parType == PAR_1RS:# OP Rs
            Xs = pars[1]
        elif parType == PAR_1RD:# OP Rd
            Xd = pars[1]
        elif parType == PAR_2F: # OP Fd, Fs
            Xd = pars[1]
            Xs = pars[2]
        elif parType == PAR_2D: # OP Dd, Ds
            Xd = pars[1]*2
            Xs = pars[2]*2
        elif parType == PAR_RF or parType == PAR_FR: # OP Rd, Fs ; OP Fd, Rs  
            Xd = pars[1]
            Xs = pars[2]
        elif parType == PAR_DF or parType == PAR_DR: # OP Dd, Fs ; OP Dd, Rs
            Xd = pars[1]*2
            Xs = pars[2]
        elif parType == PAR_FD or parType == PAR_RD: # OP Fd, Ds ; OP Rd, Ds
            Xd = pars[1]
            Xs = pars[2]*2
        elif parType == PAR_2FC: # OP Fs, Fc
            Xs = pars[1]
            Xd = pars[2]
        elif parType == PAR_2DC: # OP Ds, Dc
            Xs = pars[1]*2
            Xd = pars[2]*2
        elif parType == PAR_DEST: # OP Dest
            imm = pars[1]
        elif parType == PAR_RDES: # OP Rs, Imm
            Xs  = pars[1]
            imm = pars[2]
        elif parType == PAR_I: # OP Imm
            imm = pars[1]
        elif parType == PAR_2RI: # OP Rd,Rs,Imm
            Xd = pars[1]
            Xs = pars[2]
            imm = pars[3]
        elif parType == PAR_RID: # OP Rd, Imm
            Xd = pars[1]
            imm = pars[2]
        elif parType == PAR_RA or parType == PAR_FA or parType == PAR_AR or parType == PAR_AF: # OP Rd, Addr ; OP Fd, Addr ; OP Addr, Rs ; OP Addr, Fs
            Xd = pars[1]
            Xs = pars[2][1]
            imm = pars[2][0]
        elif parType == PAR_DA or parType == PAR_AD: #  OP Dd, Addr ; OP Addr, Ds
            Xd = pars[1]*2
            Xs = pars[2][1]
            imm = pars[2][0]
        else:
            raise SyntaxError("Illegal Parameter Type for I-Encoding @ ["+str(lineNr)+"] '"+line+"'")
            return False
            
        if imm > 65535 or imm < -32768:
            raise ValueError("Immediate out of range [-32768 to 65535] ("+str(imm)+") @ ["+str(lineNr)+"] '"+line+"'")
            return False
            
        if Xs > 31 or Xs < 0:
            raise ValueError("Source register out of range ("+str(Xs)+") @ ["+str(lineNr)+"] '"+line+"'")
            return False
            
        if Xd > 31 or Xd < 0:
            raise ValueError("Destination register out of range ("+str(Xd)+") @ ["+str(lineNr)+"] '"+line+"'")
            return False
            
        if opvalue > 0x3f or opvalue < 0:
            raise ValueError("Opcode out of range @ ["+str(lineNr)+"] '"+line+"'")
            return False
        
        value = ((imm&0xFFFF)<<16)|((Xd&0x1f)<<11)|((Xs&0x1f)<<6)|(opvalue&0x3f)
        context.code += struct.pack("<I", value)
        context.lineNr += struct.pack("<I", lineNr)
        return True
    elif inst.encodingScheme == ENCODING_J:
        opvalue = inst.opcode
        dest    = 0
        
        if parType == PAR_EMPT: pass
        elif parType == PAR_DEST: # OP Dest
            dest = pars[1]
        elif parType == PAR_I: # OP Imm
            dest = pars[1]
        else:
            raise SyntaxError("Illegal Parameter Type for J-Encoding @ ["+str(lineNr)+"] '"+line+"'")
            return False
            
        if dest > 33554431 or dest < -33554432:
            raise ValueError("Jump Distance out of range [-33554432 to 33554431] ("+str(dest)+") @ ["+str(lineNr)+"] '"+line+"'")
            return False
            
        if opvalue > 0x3f or opvalue < 0:
            raise ValueError("Opcode out of range @ ["+str(lineNr)+"] '"+line+"'")
            return False
        
        value = ((dest&0x3ffffff)<<6)|(opvalue&0x3f)
        context.code += struct.pack("<I", value)
        context.lineNr += struct.pack("<I", lineNr)
        return True
        
    raise RuntimeError("Invalid Inpuut @ ["+str(lineNr)+"] '"+line+"'")
    return False

def convertLabel(context, text, label):
    
    incValue = 4

    index = 0
    for line in text:
        if line == None: continue
        line = line.strip()
        if len(line.strip()) == 0:  continue
        if line[0] == ";": continue
        obj = re.match(r"^ *([A-Z_.$][A-Z0-9_.$]*): *([^;]+)?(?:;.*)?$",line,re.IGNORECASE)
        if obj != None:
            if(obj.group(1) == label): break
            if(len(obj.groups()) == 2):
                index += incValue
        else:
            index += incValue
    return index
    
def parseToContext(context, line, text, lineNr):
    if line == None: return
    line = line.strip()
    if len(line.strip()) == 0:
        return
    if line[0] == ";":
        return
        
    # NORMAL DLX ENCODINGS

    # PAR_EMPT | OP
    obj = re.match("^ *([A-Z]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_EMPT, [obj.group(1)], line, lineNr)
        return
        
    # PAR_1RS  | OP Rs
    # PAR_1RD  | OP Rd
    obj = re.match("^ *([A-Z]+) +R([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        try:
            encode(context, PAR_1RD, [obj.group(1), int(obj.group(2),10)], line, lineNr)
        except ValueError:
            encode(context, PAR_1RS, [obj.group(1), int(obj.group(2),10)], line, lineNr)
        return
        
    # PAR_RDES | OP Rs, Dest
    obj = re.match(r"^ *([A-Z]+) +R([0-9]+) *, *([A-Z_.$][0-9A-Z_.$]*) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_RDES, [obj.group(1),int(obj.group(2),10),convertLabel(context, text,obj.group(3))-len(context.code)], line, lineNr)
        return
        
    # PAR_RA   | OP Rd, Addr
    obj = re.match(r"^ *([A-Z]+) +R([0-9]+) *, *(-?[0-9]+)\(R([0-9]+)\) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_RA, [obj.group(1),int(obj.group(2)),(int(obj.group(3),10), int(obj.group(4)))], line, lineNr)
        return
        
    # PAR_FA   | OP Fd, Addr
    obj = re.match(r"^ *([A-Z]+) +F([0-9]+) *, *(-?[0-9]+)\(R([0-9]+)\) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_FA, [obj.group(1),int(obj.group(2)),(int(obj.group(3),10), int(obj.group(4)))], line, lineNr)
        return
        
    # PAR_DA   | OP Dd, Addr
    obj = re.match(r"^ *([A-Z]+) +D([0-9]+) *, *(-?[0-9]+)\(R([0-9]+)\) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_DA, [obj.group(1),int(obj.group(2)),(int(obj.group(3),10), int(obj.group(4)))], line, lineNr)
        return
        
    # PAR_AR   | OP Addr, Rs
    obj = re.match(r"^ *([A-Z]+) +(-?[0-9]+)\(R([0-9]+)\) *, *R([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_AR, [obj.group(1), int(obj.group(4)),(int(obj.group(2),10), int(obj.group(3)))], line, lineNr)
        return
        
    # PAR_AF   | OP Addr, Fs
    obj = re.match(r"^ *([A-Z]+) +(-?[0-9]+)\(R([0-9]+)\) *, *F([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_AF, [obj.group(1), int(obj.group(4)), (int(obj.group(2),10), int(obj.group(3)))], line, lineNr)
        return
        
    # PAR_AD   | OP Addr, Ds
    obj = re.match(r"^ *([A-Z]+) +(-?[0-9]+)\(R([0-9]+)\) *, *D([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_AD, [obj.group(1), int(obj.group(4)), (int(obj.group(2),10), int(obj.group(3)))], line, lineNr)
        return
       
    # PAR_2FC  | OP Fs, Fc       
    # PAR_2F   | OP Fd, Fs
    obj = re.match(r"^ *([A-Z]+) +F([0-9]+) *, *F([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        try:
            encode(context, PAR_2F, [obj.group(1),int(obj.group(2)), int(obj.group(3))], line, lineNr)
        except ValueError:
            encode(context, PAR_2FC, [obj.group(1),int(obj.group(2)), int(obj.group(3))], line, lineNr)
        return
    
    # PAR_2DC  | OP Ds, Dc
    # PAR_2D   | OP Dd, Ds
    obj = re.match(r"^ *([A-Z]+) +D([0-9]+) *, *D([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        try:
            encode(context, PAR_2D, [obj.group(1), int(obj.group(2)), int(obj.group(3))], line, lineNr)
        except ValueError:
            encode(context, PAR_2DC, [obj.group(1), int(obj.group(2)), int(obj.group(3))], line, lineNr)
        return
        
    # PAR_RF   | OP Rd, Fs
    obj = re.match(r"^ *([A-Z]+) +R([0-9]+) *, *F([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_RF, [obj.group(1),int(obj.group(2)), int(obj.group(3))], line, lineNr)
        return
        
    # PAR_FR   | OP Fd, Rs 
    obj = re.match(r"^ *([A-Z]+) +F([0-9]+) *, *R([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_FR, [obj.group(1),int(obj.group(2)),int(obj.group(3))], line, lineNr)
        return
        
    # PAR_DF   | OP Dd, Fs
    obj = re.match(r"^ *([A-Z]+) +D([0-9]+) *, *F([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_DF, [obj.group(1),int(obj.group(2)),int(obj.group(3))], line, lineNr)
        return
        
    # PAR_FD   | OP Fd, Ds
    obj = re.match(r"^ *([A-Z]+) +F([0-9]+) *, *D([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_FD, [obj.group(1),int(obj.group(2)),int(obj.group(3))], line, lineNr)
        return
        
    # PAR_RD   | OP Rd, Ds
    obj = re.match(r"^ *([A-Z]+) +R([0-9]+) *, *D([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_RD, [obj.group(1),int(obj.group(2)),int(obj.group(3))], line, lineNr)
        return
        
    # PAR_DR   | OP Dd, Rs
    obj = re.match(r"^ *([A-Z]+) +D([0-9]+) *, *R([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_DR, [obj.group(1),int(obj.group(2)),int(obj.group(3))], line, lineNr)
        return  
        
    # PAR_I    | OP Imm
    obj = re.match(r"^ *([A-Z]+) +#(-?[0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_I, [obj.group(1),int(obj.group(2),10)], line, lineNr)
        return
        
    # PAR_RID  | OP Rd, Imm
    obj = re.match(r"^ *([A-Z]+) +R([0-9]+) *, *#(-?[0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_RID, [obj.group(1),int(obj.group(2)),int(obj.group(3),10)], line, lineNr)
        return
        
    # PAR_2RI  | OP Rd,Rs,Imm
    obj = re.match(r"^ *([A-Z]+) +R([0-9]+) *, *R([0-9]+) *, *#(-?[0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_2RI, [obj.group(1),int(obj.group(2)),int(obj.group(3)),int(obj.group(4),10)], line, lineNr)
        return
        
    # PAR_3R   | OP Rd,Rs,Rc
    # PAR_3D   | OP Dd,Ds,Dc
    obj = re.match(r"^ *([A-Z]+) +R([0-9]+) *, *R([0-9]+) *, *R([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_3R, [obj.group(1),int(obj.group(2)),int(obj.group(3)),int(obj.group(4))], line, lineNr)
        return
        
    # PAR_3F   | OP Fd,Fs,Fc
    obj = re.match(r"^ *([A-Z]+) +F([0-9]+) *, *F([0-9]+) *, *F([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_3F, [obj.group(1),int(obj.group(2)),int(obj.group(3)),int(obj.group(4))], line, lineNr)
        return
        
    # PAR_3D   | OP Dd,Ds,Dc
    obj = re.match(r"^ *([A-Z]+) +D([0-9]+) *, *D([0-9]+) *, *D([0-9]+) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_3D, [obj.group(1),int(obj.group(2)),int(obj.group(3)),int(obj.group(4))], line, lineNr)
        return
       
    # PAR_DEST | OP Dest
    obj = re.match("^ *([A-Z]+) +([A-Z_.$][0-9A-Z_.$]*) *(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        encode(context, PAR_DEST, [obj.group(1),convertLabel(context,text,obj.group(2))-len(context.code)], line, lineNr)
        return
 
    #LABEL:
    obj = re.match(r"^ *([A-Z_.$][A-Z0-9_.$]*):? *([^;]+)?(?:;.*)?$",line,re.IGNORECASE)
    if obj != None:
        if(len(obj.groups()) == 2):
            parseToContext(context,obj.group(2), text, lineNr)
        return
        
    raise SyntaxError("Illegal Instruction @ ["+str(lineNr)+"] '"+line+"'")
    return
    
def parse(inputText, debug=False):
    context = AssembleContext()
    context.debug = debug
    text = inputText.split("\n")
    for i, s in enumerate(text):
        parseToContext(context, s, text, i)
     
    if context.debug:
        return (context.code, context.lineNr)
    return context.code