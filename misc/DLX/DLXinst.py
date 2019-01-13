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

# Encoding Formats
ENCODING_R = 0
ENCODING_I = 1
ENCODING_J = 2

# Parameter Formats
PAR_3R   =   0  # OP Rd,Rs,Rc
PAR_1RS  =   1  # OP Rs
PAR_1RD  =   2  # OP Rd
PAR_2F   =   3  # OP Fd, Fs
PAR_2D   =   4  # OP Dd, Ds
PAR_RF   =   5  # OP Rd, Fs
PAR_FR   =   6  # OP Fd, Rs 
PAR_3F   =   7  # OP Fd,Fs,Fc
PAR_3D   =   8  # OP Dd,Ds,Dc
PAR_DF   =   9  # OP Dd, Fs
PAR_FD   =  10  # OP Fd, Ds
PAR_RD   =  11  # OP Rd, Ds
PAR_DR   =  12  # OP Dd, Rs
PAR_2FC  =  13  # OP Fs, Fc
PAR_2DC  =  14  # OP Ds, Dc
PAR_DEST =  15  # OP Dest
PAR_RDES =  16  # OP Rs, Imm
PAR_I    =  17  # OP Imm
PAR_2RI  =  18  # OP Rd,Rs,Imm
PAR_RID  =  19  # OP Rd, Imm
PAR_EMPT =  20  # OP
PAR_RA   =  21  # OP Rd, Addr
PAR_FA   =  22  # OP Fd, Addr
PAR_DA   =  23  # OP Dd, Addr
PAR_AR   =  24  # OP Addr, Rs
PAR_AF   =  25  # OP Addr, Fs
PAR_AD   =  26  # OP Addr, Ds

class InstructionFormat:
    def __init__(self, opcode, functionValue, encodingScheme, parameterScheme, name):
        self.opcode = opcode
        self.functionValue = functionValue
        self.encodingScheme = encodingScheme
        self.parameterScheme = parameterScheme
        self.name = name
        
# Instruction Formats
Instructions = {

    # R Type "Special Instructions"
    "SLL":     InstructionFormat(0x00,0x04,ENCODING_R,PAR_3R,"SLL"),
    "SRL":     InstructionFormat(0x00,0x06,ENCODING_R,PAR_3R,"SRL"),
    "SRA":     InstructionFormat(0x00,0x07,ENCODING_R,PAR_3R,"SRA"),
    "ADD":     InstructionFormat(0x00,0x20,ENCODING_R,PAR_3R,"ADD"),
    "ADDU":    InstructionFormat(0x00,0x21,ENCODING_R,PAR_3R,"ADDU"),
    "SUB":     InstructionFormat(0x00,0x22,ENCODING_R,PAR_3R,"SUB"),
    "SUBU":    InstructionFormat(0x00,0x23,ENCODING_R,PAR_3R,"SUBU"),
    "AND":     InstructionFormat(0x00,0x24,ENCODING_R,PAR_3R,"AND"),
    "OR":      InstructionFormat(0x00,0x25,ENCODING_R,PAR_3R,"OR"),
    "XOR":     InstructionFormat(0x00,0x26,ENCODING_R,PAR_3R,"XOR"),
    "SEQ":     InstructionFormat(0x00,0x28,ENCODING_R,PAR_3R,"SEQ"),
    "SNE":     InstructionFormat(0x00,0x29,ENCODING_R,PAR_3R,"SNE"),
    "SLT":     InstructionFormat(0x00,0x2A,ENCODING_R,PAR_3R,"SLT"),
    "SGT":     InstructionFormat(0x00,0x2B,ENCODING_R,PAR_3R,"SGT"),
    "SLE":     InstructionFormat(0x00,0x2C,ENCODING_R,PAR_3R,"SLE"),
    "SGE":     InstructionFormat(0x00,0x2D,ENCODING_R,PAR_3R,"SGE"),
    "MOVI2S":  InstructionFormat(0x00,0x30,ENCODING_R,PAR_1RS,"MOVI2S"),
    "MOVS2I":  InstructionFormat(0x00,0x31,ENCODING_R,PAR_1RD,"MOVS2I"),
    "MOVF":    InstructionFormat(0x00,0x32,ENCODING_R,PAR_2F,"MOVF"),
    "MOVD":    InstructionFormat(0x00,0x33,ENCODING_R,PAR_2D,"MOVD"),
    "MOVFP2I": InstructionFormat(0x00,0x34,ENCODING_R,PAR_RF,"MOVFP2I"),
    "MOVI2FP": InstructionFormat(0x00,0x35,ENCODING_R,PAR_FR,"MOVI2FP"),
    
    # R Type "Floating Point Instructions"
    "ADDF":    InstructionFormat(0x01,0x00,ENCODING_R,PAR_3F,"ADDF"),
    "SUBF":    InstructionFormat(0x01,0x01,ENCODING_R,PAR_3F,"SUBF"),
    "MULTF":   InstructionFormat(0x01,0x02,ENCODING_R,PAR_3F,"MULTF"),
    "DIVF":    InstructionFormat(0x01,0x03,ENCODING_R,PAR_3F,"DIVF"),
    "ADDD":    InstructionFormat(0x01,0x04,ENCODING_R,PAR_3D,"ADDD"),
    "SUBD":    InstructionFormat(0x01,0x05,ENCODING_R,PAR_3D,"SUBD"),
    "MULTD":   InstructionFormat(0x01,0x06,ENCODING_R,PAR_3D,"MULTD"),
    "DIVD":    InstructionFormat(0x01,0x07,ENCODING_R,PAR_3D,"DIVD"),
    "CVTF2D":  InstructionFormat(0x01,0x08,ENCODING_R,PAR_DF,"CVTF2D"),
    "CVTF2I":  InstructionFormat(0x01,0x09,ENCODING_R,PAR_RF,"CVTF2I"),
    "CVTD2F":  InstructionFormat(0x01,0x0A,ENCODING_R,PAR_FD,"CVTD2F"),
    "CVTD2I":  InstructionFormat(0x01,0x0B,ENCODING_R,PAR_RD,"CVTD2I"),
    "CVTI2F":  InstructionFormat(0x01,0x0C,ENCODING_R,PAR_FR,"CVTI2F"),
    "CVTI2D":  InstructionFormat(0x01,0x0D,ENCODING_R,PAR_DR,"CVTI2D"),
    "MULT":    InstructionFormat(0x01,0x0E,ENCODING_R,PAR_3R,"MULT"),
    "DIV":     InstructionFormat(0x01,0x0F,ENCODING_R,PAR_3R,"DIV"),
    "EQF":     InstructionFormat(0x01,0x10,ENCODING_R,PAR_2FC,"EQF"),
    "NEF":     InstructionFormat(0x01,0x11,ENCODING_R,PAR_2FC,"NEF"),
    "LTF":     InstructionFormat(0x01,0x12,ENCODING_R,PAR_2FC,"LTF"),
    "GTF":     InstructionFormat(0x01,0x13,ENCODING_R,PAR_2FC,"GTF"),
    "LEF":     InstructionFormat(0x01,0x14,ENCODING_R,PAR_2FC,"LEF"),
    "GEF":     InstructionFormat(0x01,0x15,ENCODING_R,PAR_2FC,"GEF"),
    "MULTU":   InstructionFormat(0x01,0x16,ENCODING_R,PAR_3R,"MULTU"),
    "DIVU":    InstructionFormat(0x01,0x17,ENCODING_R,PAR_3R,"DIVU"),
    "EQD":     InstructionFormat(0x01,0x18,ENCODING_R,PAR_2DC,"EQD"),
    "NED":     InstructionFormat(0x01,0x19,ENCODING_R,PAR_2DC,"NED"),
    "LTD":     InstructionFormat(0x01,0x1A,ENCODING_R,PAR_2DC,"LTD"),
    "GTD":     InstructionFormat(0x01,0x1B,ENCODING_R,PAR_2DC,"GTD"),
    "LED":     InstructionFormat(0x01,0x1C,ENCODING_R,PAR_2DC,"LED"),
    "GED":     InstructionFormat(0x01,0x1D,ENCODING_R,PAR_2DC,"GED"),
    
    # "Normal Instructions"
    "J":       InstructionFormat(0x02,0x00,ENCODING_J,PAR_DEST,"J"),
    "JAL":     InstructionFormat(0x03,0x00,ENCODING_J,PAR_DEST,"JAL"),
    "BEQZ":    InstructionFormat(0x04,0x00,ENCODING_I,PAR_RDES,"BEQZ"),
    "BNEZ":    InstructionFormat(0x05,0x00,ENCODING_I,PAR_RDES,"BNEZ"),
    "BFPT":    InstructionFormat(0x06,0x00,ENCODING_I,PAR_DEST,"BFPT"),
    "BFPF":    InstructionFormat(0x07,0x00,ENCODING_I,PAR_DEST,"BFPF"),
    "ADDI":    InstructionFormat(0x08,0x00,ENCODING_I,PAR_2RI,"ADDI"),
    "ADDUI":   InstructionFormat(0x09,0x00,ENCODING_I,PAR_2RI,"ADDUI"),
    "SUBI":    InstructionFormat(0x0A,0x00,ENCODING_I,PAR_2RI,"SUBI"),
    "SUBUI":   InstructionFormat(0x0B,0x00,ENCODING_I,PAR_2RI,"SUBUI"),
    "ANDI":    InstructionFormat(0x0C,0x00,ENCODING_I,PAR_2RI,"ANDI"),
    "ORI":     InstructionFormat(0x0D,0x00,ENCODING_I,PAR_2RI,"ORI"),
    "XORI":    InstructionFormat(0x0E,0x00,ENCODING_I,PAR_2RI,"XORI"),
    "LHI":     InstructionFormat(0x0F,0x00,ENCODING_I,PAR_RID,"LHI"),
    "RFE":     InstructionFormat(0x10,0x00,ENCODING_J,PAR_EMPT,"RFE"),
    "TRAP":    InstructionFormat(0x11,0x00,ENCODING_J,PAR_I,"TRAP"),
    "JR":      InstructionFormat(0x12,0x00,ENCODING_I,PAR_1RS,"JR"),
    "JALR":    InstructionFormat(0x13,0x00,ENCODING_I,PAR_1RS,"JALR"),
    "SLLI":    InstructionFormat(0x14,0x00,ENCODING_I,PAR_2RI,"SLLI"),
    "SRLI":    InstructionFormat(0x16,0x00,ENCODING_I,PAR_2RI,"SRLI"),
    "SRAI":    InstructionFormat(0x17,0x00,ENCODING_I,PAR_2RI,"SRAI"),
    "SEQI":    InstructionFormat(0x18,0x00,ENCODING_I,PAR_2RI,"SEQI"),
    "SNEI":    InstructionFormat(0x19,0x00,ENCODING_I,PAR_2RI,"SNEI"),
    "SLTI":    InstructionFormat(0x1A,0x00,ENCODING_I,PAR_2RI,"SLTI"),
    "SGTI":    InstructionFormat(0x1B,0x00,ENCODING_I,PAR_2RI,"SGTI"),
    "SLEI":    InstructionFormat(0x1C,0x00,ENCODING_I,PAR_2RI,"SLEI"),
    "SGEI":    InstructionFormat(0x1D,0x00,ENCODING_I,PAR_2RI,"SGEI"),
    "LB":      InstructionFormat(0x20,0x00,ENCODING_I,PAR_RA,"LB"),
    "LH":      InstructionFormat(0x21,0x00,ENCODING_I,PAR_RA,"LH"),
    "LW":      InstructionFormat(0x23,0x00,ENCODING_I,PAR_RA,"LW"),
    "LBU":     InstructionFormat(0x24,0x00,ENCODING_I,PAR_RA,"LBU"),
    "LHU":     InstructionFormat(0x25,0x00,ENCODING_I,PAR_RA,"LHU"),
    "LF":      InstructionFormat(0x26,0x00,ENCODING_I,PAR_RF,"LF"),
    "LD":      InstructionFormat(0x27,0x00,ENCODING_I,PAR_RD,"LD"),
    "SB":      InstructionFormat(0x28,0x00,ENCODING_I,PAR_AR,"SB"),
    "SH":      InstructionFormat(0x29,0x00,ENCODING_I,PAR_AR,"SH"),
    "SW":      InstructionFormat(0x3B,0x00,ENCODING_I,PAR_AR,"SW"),
    "SF":      InstructionFormat(0x3E,0x00,ENCODING_I,PAR_AF,"SF"),
    "SD":      InstructionFormat(0x3F,0x00,ENCODING_I,PAR_AD,"SD"),
    
    # Special Opcodes meant for testing and debugging - not in normal DLX listings
    "DEBUG":   InstructionFormat(0x30,0x00,ENCODING_J,PAR_I,"DEBUG"),
    "HALT":    InstructionFormat(0x31,0x00,ENCODING_J,PAR_EMPT,"HALT")
}

# Instructions by opcode function combination
InstructionsOF = {(v.opcode, v.functionValue): v for k, v in Instructions.iteritems()}