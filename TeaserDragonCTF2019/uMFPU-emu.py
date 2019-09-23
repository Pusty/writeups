import bitstring
import struct
import sys
import math

#
# http://micromegacorp.com/downloads/documentation/uMFPU-V3_1%20Datasheet.pdf

data = [  0x07, 0x01, 0x7f, 0xae, 0x5c, 0x7f, 0x02, 0x80, 0xb8, 0x65, 0x10, 0x01, 0x08, 0x66, 0x18, 0x01, 
  0x08, 0x6e, 0x19, 0xc7, 0x02, 0x10, 0x10, 0xc9, 0x00, 0x2f, 0x10, 0x11, 0xc9, 0x00, 0x97, 0x10, 
  0x12, 0x01, 0x12, 0x9e, 0x11, 0x90, 0x13, 0x4b, 0xa9, 0xdc, 0x18, 0x7f, 0x94, 0x65, 0x10, 0x01, 
  0x08, 0x66, 0x18, 0x01, 0x08, 0x6e, 0x1b, 0x00, 0xe4, 0xd2, 0xa8, 0x4b, 0xad, 0xcb, 0x2b, 0x5b, 
  0x56, 0x38, 0xa9, 0x4d, 0xfe, 0x98, 0xdb, 0x2c, 0x76, 0x8f, 0xd2, 0x4b, 0x9a, 0xcc, 0xe9, 0xaf, 
  0x0e, 0xdd, 0x4f, 0x36, 0x18, 0x5e, 0xb9, 0x7c, 0xf0, 0xa7, 0xd4, 0x4b, 0xf1, 0xde, 0xa8, 0x4a, 
  0xb6, 0xf4, 0xaa, 0x49, 0x19, 0xdc, 0x55, 0x5a, 0x63, 0xdd, 0x14, 0x4a, 0xa5, 0xde, 0x47, 0x4a, 
  0x1a, 0x69, 0xb9, 0xcf, 0x48, 0xdc, 0xf2, 0x34, 0x40, 0xdd, 0xa9, 0xfe, 0x19, 0x5e, 0xf9, 0x44, 
  0xfb, 0x8b, 0xcc, 0x27, 0x74, 0xfc, 0xed, 0x24, 0x76, 0xb9, 0x88, 0x4b, 0x9b, 0xdc, 0x3e, 0xa8, 
  0x4f, 0xae, 0xc6, 0x25, 0x7f, 0xfc, 0xcf, 0x27, 0x79, 0xbb, 0x87, 0x4b, 0x9b, 0xdc, 0x3e, 0x4b, 
  0x07, 0x00, 0x18, 0xc7, 0x02, 0x10, 0x10, 0xc9, 0x00, 0x2f, 0x10, 0x11, 0xc9, 0x00, 0x97, 0x10, 
  0x12, 0x01, 0x12, 0x9e, 0x11, 0x90, 0x13, 0x4b, 0xa9, 0xdc, 0x18, 0x7f, 0x94, 0x07, 0x18, 0x00, 
  0x80, 0x00, 0x00, 0x00, 0x98, 0x65, 0x10, 0x01, 0x08, 0x66, 0x18, 0x01, 0x08, 0x6e, 0x19, 0xc7, 
  0x31, 0x10, 0x10, 0xc9, 0x00, 0x2f, 0x10, 0x11, 0xc9, 0x00, 0x77, 0x10, 0x12, 0x01, 0x12, 0x9e, 
  0x11, 0x90, 0x13, 0x17, 0xdb, 0x41, 0xdc, 0x7f, 0x94, 0x65, 0x10, 0x01, 0x08, 0x66, 0x18, 0x01, 
  0x08, 0x6e, 0x1b, 0x00, 0xde, 0x09, 0xab, 0x07, 0xa6, 0xa4, 0x5e, 0x15, 0xfe, 0xf9, 0xf6, 0x58, 
  0xe1, 0x68, 0xdb, 0xee, 0xcf, 0x76, 0x74, 0x6e, 0xcc, 0x6f, 0xfc, 0x01, 0xb2, 0x7f, 0xfc, 0x7a, 
  0xd1, 0xea, 0xa9, 0x4f, 0xf0, 0x03, 0x4e, 0x3b, 0xae, 0x92, 0x53, 0x8c, 0xcd, 0x4c, 0x3a, 0xe7, 
  0x84, 0xe1, 0x43, 0xc6, 0xa5, 0x62, 0xde, 0x22, 0xeb, 0x91, 0x9d, 0x66, 0xd5, 0x24, 0x74, 0x92, 
  0xcf, 0xd0, 0x4e, 0xb1, 0xf7, 0x32, 0xee, 0x75, 0x5f, 0x41, 0xac, 0x17, 0x07, 0x00, 0x18, 0xc7, 
  0x31, 0x10, 0x10, 0xc9, 0x00, 0x2f, 0x10, 0x11, 0xc9, 0x00, 0x77, 0x10, 0x12, 0x01, 0x12, 0x9e, 
  0x11, 0x90, 0x13, 0x17, 0xdb, 0x41, 0xdc, 0x7f, 0x94, 0x07, 0x18, 0x00, 0x80, 0x00, 0x00, 0x00, 
  0xdc, 0x65, 0x10, 0x01, 0x08, 0x66, 0x18, 0x01, 0x08, 0x6e, 0x19, 0xc7, 0x58, 0x10, 0x10, 0xc9, 
  0x00, 0x2f, 0x10, 0x11, 0xc9, 0x00, 0xbb, 0x10, 0x12, 0x01, 0x12, 0x9e, 0x11, 0x90, 0x13, 0x73, 
  0xd4, 0x01, 0xac, 0x7f, 0x94, 0x65, 0x10, 0x01, 0x08, 0x66, 0x18, 0x01, 0x08, 0x6e, 0x1b, 0x00, 
  0xd3, 0x30, 0xb2, 0x5b, 0xa8, 0x05, 0xb1, 0x4b, 0xa8, 0x05, 0xba, 0x60, 0xaa, 0xbc, 0xd4, 0xce, 
  0xac, 0xbc, 0xd4, 0x1d, 0xad, 0x91, 0xd6, 0x32, 0x6a, 0x4f, 0xb9, 0xe3, 0xaf, 0xa4, 0x71, 0xd6, 
  0x09, 0x91, 0xd0, 0x73, 0xac, 0x31, 0xed, 0xe3, 0xa9, 0x7e, 0x2b, 0x8c, 0x53, 0x00, 0xdd, 0xdd, 
  0xa4, 0x00, 0xde, 0xdd, 0xbc, 0x00, 0xdf, 0xdd, 0xb4, 0x00, 0xd5, 0xdd, 0x94, 0x02, 0xd8, 0x72, 
  0xa1, 0xaf, 0x9c, 0x72, 0xaf, 0x9e, 0xd6, 0xee, 0xa8, 0xc1, 0xd1, 0x09, 0xad, 0x00, 0xd4, 0x63, 
  0xaa, 0x11, 0xd3, 0x63, 0xa4, 0x00, 0xd2, 0xb0, 0xa5, 0x00, 0xd3, 0xb0, 0xa6, 0x00, 0xdc, 0xb0, 
  0xa7, 0x00, 0xd4, 0xb2, 0xaa, 0xc0, 0xd3, 0xb2, 0xa4, 0xc3, 0xd7, 0x08, 0xad, 0x11, 0xd2, 0x09, 
  0xa1, 0x00, 0xd4, 0xb1, 0xaa, 0x00, 0xd8, 0xb2, 0xac, 0xbc, 0xd9, 0xce, 0xad, 0x00, 0xd5, 0xc6, 
  0xe4, 0x83, 0x84, 0xcc, 0x11, 0x0d, 0xd3, 0x7f, 0xac, 0x82, 0xd4, 0xc8, 0x07, 0x00, 0x18, 0xc7, 
  0x58, 0x10, 0x10, 0xc9, 0x00, 0x2f, 0x10, 0x11, 0xc9, 0x00, 0xbb, 0x10, 0x12, 0x01, 0x12, 0x9e, 
  0x11, 0x90, 0x13, 0x73, 0xd4, 0x01, 0xac, 0x7f, 0x94, 0x07, 0x18, 0x00, 0x80, 0x00, 0x00, 0x00, 
  0x05, 0x7b, 0x7f, 0xbd, 0x7f, 0x80, 0x00, 0x00, 0x06, 0xbe, 0x7f, 0x7a, 0x7f, 0xa5, 0x80, 0x00, 
  0x51, 0x01, 0x18, 0x7f, 0x90, 0x01, 0x19, 0x7f, 0x90, 0x01, 0x1a, 0x7f, 0x90, 0x01, 0x01, 0xae, 
  0xfe, 0x01, 0x12, 0xc3, 0x01, 0x01, 0x11, 0xbd, 0x11, 0xc3, 0x01, 0x01, 0x10, 0x9d, 0x11, 0x01, 
  0x18, 0x9c, 0x10, 0x9d, 0x12, 0x07, 0x10, 0x19, 0x07, 0x13, 0x1a, 0x07, 0x19, 0x10, 0x7f, 0xb0, 
  0x01, 0x00, 0xc2, 0x1a, 0x07, 0x00, 0x11, 0x07, 0x19, 0x10, 0x7f, 0xa9, 0xbd, 0x19, 0xba, 0x19, 
  0x18, 0x84, 0x50, 0x00, 0x2a, 0x01, 0x1a, 0x7f, 0x92, 0x01, 0x19, 0x7f, 0x92, 0x01, 0x18, 0x7f, 
  0x92, 0x80, 0x00, 0x00, 0x18, 0x01, 0x02, 0xae, 0x10, 0x01, 0x10, 0xc3, 0x02, 0x01, 0x01, 0x91, 
  0x80, 0x00, 0xdb, 0x03, 0xc1, 0x10, 0xdb, 0xff, 0x01, 0x11, 0x7f, 0xff, 0x80, 0x00, 0x00, 0x00, 
  0x18, 0x01, 0x02, 0xae, 0x10, 0x01, 0x10, 0xc3, 0x02, 0x01, 0x01, 0x91, 0x80, 0x00, 0xdd, 0x03, 
  0xc1, 0x10, 0xdb, 0xff, 0x01, 0x00, 0x7f, 0xff, 0x80, 0x00, 0x00, 0x00]
  
data = data + ([0]*(0x1024-len(data)))  

FLAG_INPUT = "0123456789ABCDEF" #"uMFlagPwningUnit"

ip = 0
status = 0
A = 0
X = 0 

matrixAStart = 0
matrixARows = 0
matrixAColumns = 0

matrixBStart = 0
matrixBRows = 0
matrixBColumns = 0


reg = [0] * 128
returnAddresses = []
currentContextAddress = [0]

stringBufferStart = 0
stringBufferLength = 0

debug = 0
    
def debug_print(msg):
    if not 0x250 in currentContextAddress: # for this challenge seeing the self modifying code sequence in a trace doesn't help
        print(("[%04X] : " % (ip))+msg)
    
    
    
def emu(code):
    global ip, status, A,X, returnAddresses, currentContextAddress, debug
    global matrixAStart, matrixARows, matrixAColumns
    global matrixBStart, matrixBRows, matrixBColumns
    global stringBufferStart, stringBufferLength
    op = code[ip]
    if op == 0x07:
        mm = code[ip+1]
        nn = code[ip+2]
        debug_print("COPY %d %d" % (mm,nn))
        reg[nn] = reg[mm]
        ip = ip + 3
        return True
    elif op == 0xAE:
        bb = bitstring.Bits(uint=code[ip+1], length=8).unpack('int')[0]
        debug_print("LSETI %d" % bb)
        reg[A] = bb
        ip = ip + 2
        return True
    elif op == 0x7F:
        fn = code[ip+1]
        debug_print("EECALL %04X" % (fn*4))
        returnAddresses.append(ip+2)
        currentContextAddress.append(fn*4)
        ip = (fn*4)+1 # skip validating
        return True
    elif op == 0x80:
        debug_print("RETURN")
        if len(returnAddresses) == 0:
            ip = ip + 1
            return False
        ip = returnAddresses[-1]
        returnAddresses = returnAddresses[:-1]
        currentContextAddress = currentContextAddress[:-1]
        return True
    elif op == 0x65:
        nn = code[ip+1]
        b1 = code[ip+2]
        b2 = code[ip+3]
        debug_print("SELECTMA %d %d %d" % (nn, b1, b2))
        matrixAStart = nn
        matrixARows = b1
        matrixAColumns = b2
        ip = ip + 4
        return True
    elif op == 0x66:
        nn = code[ip+1]
        b1 = code[ip+2]
        b2 = code[ip+3]
        debug_print("SELECTMB %d %d %d" % (nn, b1, b2))
        matrixBStart = nn
        matrixBRows = b1
        matrixBColumns = b2
        ip = ip + 4
        return True
    elif op == 0x6E:
        bb = code[ip+1]
        if bb <= 0x20 or bb >= 0x29: #Inverse , Decomposition 
            debug_print("MOP %d" % (bb)) # Copy matrix A to matrix B
            ip = ip + 2
        else:
            am = code[ip+2]
            da = code[ip+3:ip+3+am]
            debug_print("MOP %d %d %s" % (bb, am, da))
           
        if bb == 0x01:
            for h in range(matrixARows):
                for w in range(matrixAColumns):
                    reg[matrixAStart+h*matrixAColumns+w] = reg[matrixAStart+h*matrixAColumns+w] + reg[0]
            # add scalar
        elif bb == 0x13:
            for h in range(matrixARows):
                for w in range(matrixAColumns):
                    reg[matrixAStart+h*matrixAColumns+w] = reg[matrixBStart+w*matrixAColumns+h]
            # MA = transpose MB
        elif bb == 0x19:
            for h in range(matrixARows):
                for w in range(matrixAColumns):
                    reg[matrixBStart+h*matrixAColumns+w] = reg[matrixAStart+h*matrixAColumns+w]
            # B = A
        elif bb == 0x1b:
            for h in range(matrixBRows):
                for w in range(matrixBColumns):
                    reg[matrixAStart+h*matrixBColumns+w] = reg[matrixBStart+h*matrixBColumns+w]
            # A = B
        else:
            debug_print("Not implemented...")
        
        return True
    elif op == 0xC7:
        bb = code[ip+1]
        debug_print("LONGUBYTE %02X" % (bb))
        reg[0] = bb
        ip = ip + 2
        return True
    elif op == 0x10:
        nn = code[ip+1]
        debug_print("COPY0 %d" % (nn))
        reg[nn] = reg[0]
        ip = ip + 2
        return True
    elif op == 0x82:
        cc = code[ip+1]
        bb = bitstring.Bits(uint=code[ip+2], length=8).unpack('int')[0]
        ip = ip + 3
        if cc == 0x50:
            debug_print("BRANZ %02X" % (bb))
            if status == False:
                ip = ip + bb
        elif cc == 0x51:
            debug_print("BRAPZ %02X" % (bb))
            if status == True:
                ip = ip + bb
        elif cc == 0x72:
            debug_print("BRALT %02X" % (bb))
        elif cc == 0x62:
            debug_print("BRALE %02X" % (bb))
        elif cc == 0x70:
            debug_print("BRAGT %02X" % (bb))
        elif cc == 0x60:
            debug_print("BRAGE %02X" % (bb))
        elif cc == 0x71:
            debug_print("BRAPZ %02X" % (bb))
        elif cc == 0x73:
            debug_print("BRAMZ %02X" % (bb))
        else:
            debug_print("BRA %02X %02X" % (cc,bb))
        #ip = ip + bb
        return True
    elif op == 0x83:
        b = struct.unpack(">H", chr(code[ip+1])+chr(code[ip+2]))[0]
        debug_print("JMP %04X" % (b))
        #ip = ip + 3
        ip = currentContextAddress[-1]+1+b
        return True
    elif op == 0x84:
        cc = code[ip+1]
        b = struct.unpack(">H", chr(code[ip+2])+chr(code[ip+3]))[0]
        ip = ip + 4
        if cc == 0x50:
            debug_print("JMPNZ %04X" % (b))
            if status == False:
                ip = currentContextAddress[-1]+1+b
        elif cc == 0x51:
            debug_print("JMPZ %04X" % (b))
            if status == True:
                ip = currentContextAddress[-1]+1+b
        elif cc == 0x72:
            debug_print("JMPLT %04X" % (b))
        elif cc == 0x62:
            debug_print("JMPLE %04X" % (b))
        elif cc == 0x70:
            debug_print("JMPGT %04X" % (b))
        elif cc == 0x60:
            debug_print("JMPGE %04X" % (b))
        elif cc == 0x71:
            debug_print("JMPPZ %04X" % (b))
        elif cc == 0x73:
            debug_print("JMPMZ %04X" % (b))
        else:
            debug_print("JMP %02X %04X" % (cc,b))
        return True
        
    elif op == 0xC9:
        b = struct.unpack(">H", chr(code[ip+1])+chr(code[ip+2]))[0]
        debug_print("LONGUWORD %04X" % (b))
        reg[0] = b
        ip = ip + 3
        return True
    elif op == 0x01:
        nn = code[ip+1]
        debug_print("SELECTA %d" % (nn))
        A = nn
        ip = ip + 2
        return True
    elif op == 0x90:
        nn = code[ip+1]
        b = struct.unpack(">I", chr(code[ip+2])+chr(code[ip+3])+chr(code[ip+4])+chr(code[ip+5]))[0]
        debug_print("LWRITE %d %08X" % (nn, b))
        reg[nn] = b
        ip = ip + 6
        return True
    elif op == 0x18:
        b = struct.unpack(">f", chr(code[ip+1])+chr(code[ip+2])+chr(code[ip+3])+chr(code[ip+4]))[0]
        debug_print("FWRITEX %f" % (b))
        reg[X] = b
        ip = ip + 5
        return True
    elif op == 0x00:
        debug_print("NOP")
        ip = ip + 1
        return True
    elif op == 0xE3:
        d = []
        o = 0
        while code[ip+1+o] != 0:
            d.append(chr(code[ip+1+o]))
            o = o + 1
        debug_print("STRSET %s" % (''.join(d)))
        status = True # always right, right?
        ip = ip + 1 + len(d)
        return True
    elif op == 0xE4:
        nn = code[ip+1]
        mm = code[ip+2]
        debug_print("STRSEL %d %d" % (nn,mm))
        stringBufferStart = nn
        stringBufferLength = mm
        ip = ip + 3
        return True
    elif op == 0xE6:
        d = []
        o = 0
        while code[ip+1+o] != 0:
            d.append(chr(code[ip+1+o]))
            o = o + 1
        debug_print("STRCMP %s" % (''.join(d)))
        status = True # always right, right?
        ip = ip + 1 + len(d)
        return True
    elif op == 0xE8:
        d = []
        o = 0
        while code[ip+1+o] != 0:
            d.append(chr(code[ip+1+o]))
            o = o + 1
        debug_print("STRFCHR %s" % (''.join(d)))
        ip = ip + 1 + len(d)
        return True
    elif op == 0xE9:
        bb = code[ip+1]
        debug_print("STRFIELD %02X" % (bb))
        stringBufferStart = bb
        ip = ip + 2
        return True
    elif op == 0xEE:
        debug_print("STRINC")
        stringBufferStart = stringBufferStart + 1
        stringBufferLength = 0
        ip = ip + 1
        return True
    elif op == 0xDE:
        ee = code[ip+1]*4
        bc = code[ip+2]
        dc = code[ip+3:ip+3+bc]
        debug_print("EEWRITE %04X %d %s" %(ee, bc, dc))
        for i in range(bc):
            code[ee+i] = dc[i]
        ip = ip + 3+bc
        return True
    elif op == 0x70:
        bc = code[ip+1]
        dc = code[ip+2:ip+2+(bc*4)]
        dc = [struct.unpack(">I", chr(dc[i*4])+chr(dc[1+i*4])+chr(dc[2+i*4])+chr(dc[3+i*4]))[0] for i in range(bc)]  
        debug_print("WRBLK %d %s" % (bc, dc))
        # I don't know where in the documentation this is mention, but through the power of guessing this is what I came to and it *just works*
        for i in range(bc):
            reg[X+i] = dc[i]
        ip = ip +2+ bc*4
        return True
    elif op == 0x06:
        debug_print("CLR0")
        reg[0] = 0
        ip = ip + 1
        return True
    elif op == 0x91:
        b = struct.unpack(">I", chr(code[ip+1])+chr(code[ip+2])+chr(code[ip+3])+chr(code[ip+4]))[0]
        debug_print("LWRITEA %08X" % (b))
        reg[A] = b
        ip = ip + 5
        return True
    elif op == 0x9C:
        nn = code[ip+1]
        debug_print("LSET %d" % (nn))
        reg[A] = reg[nn]
        ip = ip + 2
        return True
    elif op == 0x9D:
        nn = code[ip+1]
        debug_print("LADD %d" % (nn))
        reg[A] = reg[A] + reg[nn]
        ip = ip + 2
        return True
    elif op == 0x9E:
        nn = code[ip+1]
        debug_print("LSUB %d" % (nn))
        reg[A] = reg[A] - reg[nn]
        ip = ip + 2
        return True
    elif op == 0x9F:
        nn = code[ip+1]
        debug_print("LMUL %d" % (nn))
        reg[A] = reg[A] * reg[nn]
        ip = ip + 2
        return True
    elif op == 0xA0:
        nn = code[ip+1]
        debug_print("LDIV %d" % (nn))
        reg[A] = reg[A] / reg[nn]
        ip = ip + 2
        return True
    elif op == 0xB5:
        bb = code[ip+1]
        debug_print("LUCMPI %02X" % (bb))
        debug_print("Compare %d(%08X) == %02X" % (A,reg[A],bb))
        status = (reg[A] == bb) # we just need the zero flag so this is ok
        ip = ip + 2
        return True
    elif op == 0xBA:
        mm = code[ip+1]
        nn = code[ip+2]
        debug_print("LUCMP2 %d %d" % (mm,nn))
        debug_print("Compare %d(%08X) == %d(%08X)" % (nn,reg[nn],mm, reg[mm]))
        status = (reg[nn] == reg[mm]) # we just need the zero flag so this is ok
        ip = ip + 3
        return True
    elif op == 0xBD:
        nn = code[ip+1]
        debug_print("LINC %d" % (nn))
        reg[nn] = reg[nn] + 1
        ip = ip + 2
        return True
    elif op == 0xBE:
        nn = code[ip+1]
        debug_print("LDEC %d" % (nn))
        reg[nn] = reg[nn] - 1
        ip = ip + 2
        return True
    elif op == 0xC0:
        nn = code[ip+1]
        debug_print("LAND %d" % (nn))
        reg[A] = reg[A] & reg[nn]
        ip = ip + 2
        return True
    elif op == 0xC1:
        nn = code[ip+1]
        debug_print("LOR %d" % (nn))
        reg[A] = reg[A]  | reg[nn]
        ip = ip + 2
        return True
    elif op == 0xC2:
        nn = code[ip+1]
        debug_print("LXOR %d" % (nn))
        reg[A] = reg[A] ^ reg[nn]
        ip = ip + 2
        return True
    elif op == 0xC3:
        nn = code[ip+1]
        debug_print("LSHIFT %d" % (nn))
        v = reg[nn]
        if v > 0:
            reg[A] = reg[A] << reg[nn]
        else:
            reg[A] = reg[A] >> -(reg[nn])
            # if shift < -64 it's archimetric not important for this though though
        ip = ip + 2
        return True
    elif op == 0x03:
        nn = code[ip+1]
        debug_print("CLR %d" % (nn))
        reg[nn] = 0
        ip = ip + 2
        return True
    elif op == 0x02:
        nn = code[ip+1]
        debug_print("SELECTX %d" % (nn))
        X = nn
        ip = ip + 2
        return True
    elif op == 0x0D:
        debug_print("ALOADX")
        reg[A] = reg[X]
        X = X + 1
        ip = ip + 1
        return True
    elif op == 0x7A:
        nn = code[ip+1]
        debug_print("LOADIND %d" % (nn))
        reg[0] = reg[reg[nn]]
        debug_print("Load %08X from %d" % (reg[0], reg[nn]))
        ip = ip + 2
        return True
    elif op == 0x7B:
        nn = code[ip+1]
        debug_print("SAVEIND %d" % (nn))
        reg[reg[nn]] = reg[A]
        debug_print("Saved %08X into %d" % (reg[A], reg[nn]))
        ip = ip + 2
        return True
    elif op == 0xA5:
        debug_print("LSET0")
        ip = ip + 1
        reg[A] = reg[0]
        return True
    elif op == 0xA6:
        debug_print("LADD0")
        ip = ip + 1
        reg[A] = reg[A] + reg[0]
        return True
    elif op == 0xA7:
        debug_print("LSUB0")
        ip = ip + 1
        reg[A] = reg[A] - reg[0]
        return True
    elif op == 0xA8:
        debug_print("LMUL0")
        ip = ip + 1
        reg[A] = reg[A] * reg[0]
        return True
    elif op == 0xA9:
        debug_print("LDIV0")
        ip = ip + 1
        reg[A] = reg[A] / reg[0]
        return True
    elif op == 0xDB:
        ee = code[ip+1]*4
        debug_print("EESAVEA %d" % (ee))
        code[ee] = reg[A]&0x0FF
        code[ee+1] = (reg[A]>>8)&0x0FF
        code[ee+2] = (reg[A]>>16)&0x0FF
        code[ee+3] = (reg[A]>>24)&0x0FF
        debug_print("Write %08X to %04X" % (reg[A], ee))
        ip = ip + 2
        return True
    elif op == 0xDD:
        ee = code[ip+1]*4
        debug_print("EELOADA %d" % (ee))
        reg[A] = code[ee] | (code[ee+1]<<8) | (code[ee+2]<<16) | (code[ee+3]<<24)
        debug_print("Read %08X from %04X" % (reg[A], ee))
        ip = ip + 2
        return True
    elif op == 0xFC:
        bb = code[ip+1]
        debug_print("READVAR %d" % (bb)) 
        if bb == 14: # Current length of string buffer
            reg[0] = 0
        elif bb == 17: # Read current character
            PWINPUT = "__"+FLAG_INPUT
            reg[0] = ord(PWINPUT[stringBufferStart])
            print("Read Input Nr: "+str(stringBufferStart))
        else:
            print("Not implemented...")
        ip = ip + 2
        return True
        
    print(hex(op))
    return False
  
  
def execute():
    global ip, status
    ip = 0
    status = 0
    for i in range(len(reg)):
        reg[i] = 0
    
    ip = 0 
    currentContextAddress = [ip] # relevant for JMP as it's relative to the function beginning
    print("Function %04X:" % ip)
    ip = ip + 1
    start = ip
    while emu(data):
        pass 
    print("================")

        
execute()