# DLX ("Deluxe")

## Environment

- learn architecture
- PC contains the address of the next instruction to execute
- 32 32bit Integer Registers
- R0..R31
- everything from R1 to R31 can be arbitrary used
- Load-Store architecture
- Register-Register architecture
- R0 is fixed to the value 0 and can only be read from
- R31 contains the return address of subroutine calls
- 32 32bit Floating Point Registers
- there are 32 Single Precision Floating Point Registers from F0 to F31 which can be arbitrary used
- for simplification there are Double Precision Floating Point Registers D0 to D15 which are in fact just two sequential Single Precision Floating Point Register
- Floating Point Status Register (FPSR) for holding the result of Floating Point comparisons
- Memory is in big-endian format and references to it are assumed to be aligned to the respective read/write size


## Instructions

#### Notation

- E(...)        Sign Extend content
- U(...)        Read content as an Unsigned Integer
- convert(...)  Convert between formats using fitting methods
- RegSpecial    Not further specified "Special Register"
- FPSR          Floating Point Status Register
- MEM[Addr]     32bit Read/Write at Addr
- Dest          signed 26bit offset
- Imm           signed or unsigned 16bit immediate value
- Xd            Destination Register
- Xs            Source Register
- Xc            Additional Register

| Opcode | Function | Mnemonic | Parameters | Encoding | Expression                     | Notes                                                               |
|--------|----------|----------|------------|----------|--------------------------------|---------------------------------------------------------------------|
| 00     | 04       | SLL      | Rd,Rs,Rc   |     R    | Rd = Rs << (Rc&0x1f)           | Shift Left Logical; Only 5 bits of Rc used                          |
| 00     | 06       | SRL      | Rd,Rs,Rc   |     R    | Rd = U(Rs) >> (Rc&0x1f)        | Shift Right Logical; Only 5 bits of Rc used                         |
| 00     | 07       | SRA      | Rd,Rs,Rc   |     R    | Rd = E(Rs) >> (Rc&0x1f)        | Shift Right Arithmetic; Only 5 bits of Rc used                      |
| 00     | 20       | ADD      | Rd,Rs,Rc   |     R    | Rd = Rs + Rc                   | Add signed                                                          |
| 00     | 21       | ADDU     | Rd,Rs,Rc   |     R    | Rd = Rs + Rc                   | Add unsigned                                                        |
| 00     | 22       | SUB      | Rd,Rs,Rc   |     R    | Rd = Rs - Rc                   | Subtract signed                                                     |
| 00     | 23       | SUBU     | Rd,Rs,Rc   |     R    | Rd = Rs - Rc                   | Subtract unsigned                                                   |
| 00     | 24       | AND      | Rd,Rs,Rc   |     R    | Rd = Rs & Rc                   | Bitwise And Registers                                               |
| 00     | 25       | OR       | Rd,Rs,Rc   |     R    | Rd = Rs | Rc                   | Bitwise Or Registers                                                |
| 00     | 26       | XOR      | Rd,Rs,Rc   |     R    | Rd = Rs ^ Rc                   | Bitwise Exclusive Or Registers                                      |
| 00     | 28       | SEQ      | Rd,Rs,Rc   |     R    | Rd = (Rs == Rc?1:0)            | Set Equal                                                           |
| 00     | 29       | SNE      | Rd,Rs,Rc   |     R    | Rd = (Rs != Rc?1:0)            | Set Not Equal                                                       |
| 00     | 2A       | SLT      | Rd,Rs,Rc   |     R    | Rd = (Rs < Rc?1:0)             | Set Less Than                                                       |
| 00     | 2B       | SGT      | Rd,Rs,Rc   |     R    | Rd = (Rs > Rc?1:0)             | Set Greater Than                                                    |
| 00     | 2C       | SLE      | Rd,Rs,Rc   |     R    | Rd = (Rs <= Rc?1:0)            | Set Less or Equal Than                                              |
| 00     | 2D       | SGE      | Rd,Rs,Rc   |     R    | Rd = (Rs >= Rc?1:0)            | Set Greater or Equal Than                                           |
| 00     | 30       | MOVI2S   | Rs         |     R    | RegSpecial = Rs                | Move Register Content to Special Register                           |
| 00     | 31       | MOVS2I   | Rd         |     R    | Rd = RegSpecial                | Move Special Register Content to Register                           |
| 00     | 32       | MOVF     | Fd, Fs     |     R    | Fd = Fs                        | Move Single Precision Floating Point                                |
| 00     | 33       | MOVD     | Dd, Ds     |     R    | Dd = Ds                        | Move Double Precision Floating Point                                |
| 00     | 34       | MOVFP2I  | Rd, Fs     |     R    | Rd = Fs                        | Move Float to Integer; No conversion is happening                   |
| 00     | 35       | MOVI2FP  | Fd, Rs     |     R    | Fd = Rs                        | Move Integer to Float; No conversion is happening                   |
| 01     | 00       | ADDF     | Fd,Fs,Fc   |     R    | Fd = Fs + Fc                   | Add Single Precision Floating Points                                |
| 01     | 01       | SUBF     | Fd,Fs,Fc   |     R    | Fd = Fs - Fc                   | Subtract Single Precision Floating Points                           |
| 01     | 02       | MULTF    | Fd,Fs,Fc   |     R    | Fd = Fs * Fc                   | Multiply Single Precision Floating Points                           |
| 01     | 03       | DIVF     | Fd,Fs,Fc   |     R    | Fd = Fs / Fc                   | Divide Single Precision Floating Points                             |
| 01     | 04       | ADDD     | Dd,Ds,Dc   |     R    | Dd = Ds + Dc                   | Add Double Precision Floating Points                                |
| 01     | 05       | SUBD     | Dd,Ds,Dc   |     R    | Dd = Ds - Dc                   | Subtract Double Precision Floating Points                           |
| 01     | 06       | MULTD    | Dd,Ds,Dc   |     R    | Dd = Ds * Dc                   | Multiply Double Precision Floating Points                           |
| 01     | 07       | DIVD     | Dd,Ds,Dc   |     R    | Dd = Ds / Dc                   | Divide Double Precision Floating Points                             |
| 01     | 08       | CVTF2D   | Dd,Fs      |     R    | Dd = convert(Fs)               | Convert Single Precision to Double                                  |
| 01     | 09       | CVTF2I   | Rd,Fs      |     R    | Rd = convert(Fs)               | Convert Single Precision to Integer                                 |
| 01     | 0A       | CVTD2F   | Fd,Ds      |     R    | Fd = convert(Ds)               | Convert Double Precision to Single                                  |
| 01     | 0B       | CVTD2I   | Rd,Ds      |     R    | Rd = convert(Ds)               | Convert Double Precision to Integer                                 |
| 01     | 0C       | CVTI2F   | Fd,Rs      |     R    | Fd = convert(Rs)               | Convert Integer to Single Precision                                 |
| 01     | 0D       | CVTI2D   | Dd,Rs      |     R    | Dd = convert(Rs)               | Convert Integer to Double Precision                                 |
| 01     | 0E       | MULT     | Rd,Rs,Rc   |     R    | Rd = Rs * Rc                   | Multiply Signed Registers                                           |
| 01     | 0F       | DIV      | Rd,Rs,Rc   |     R    | Rd = Rs / Rc                   | Divide Signed Registers                                             |
| 01     | 10       | EQF      | Fs, Fc     |     R    | FPSR = (Fs == Fc?1:0)          | Set Floating Point Status If Equal Single Precision                 |
| 01     | 11       | NEF      | Fs, Fc     |     R    | FPSR = (Fs != Fc?1:0)          | Set Floating Point Status If Not Equal Single Precision             |
| 01     | 12       | LTF      | Fs, Fc     |     R    | FPSR = (Fs < Fc?1:0)           | Set Floating Point Status If Less Than Single Precision             |
| 01     | 13       | GTF      | Fs, Fc     |     R    | FPSR = (Fs > Fc?1:0)           | Set Floating Point Status If Greater Than Single Precision          |
| 01     | 14       | LEF      | Fs, Fc     |     R    | FPSR = (Fs <= Fc?1:0)          | Set Floating Point Status If Less or Equal Than Single Precision    |
| 01     | 15       | GEF      | Fs, Fc     |     R    | FPSR = (Fs >= Fc?1:0)          | Set Floating Point Status If Greater or Equal Than Single Precision |
| 01     | 16       | MULTU    | Rd,Rs,Rc   |     R    | Rd = U(Rs) * U(Rc)             | Multiply Unsigned Registers                                         |
| 01     | 17       | DIVU     | Rd,Rs,Rc   |     R    | Rd = U(Rs) / U(Rc)             | Divide Unsigned Registers                                           |
| 01     | 18       | EQD      | Ds, Dc     |     R    | FPSR = (Ds == Dc?1:0)          | Set Floating Point Status If Equal Double Precision                 |
| 01     | 19       | NED      | Ds, Dc     |     R    | FPSR = (Ds != Dc?1:0)          | Set Floating Point Status If Not Equal Double Precision             |
| 01     | 1A       | LTD      | Ds, Dc     |     R    | FPSR = (Ds < Dc?1:0)           | Set Floating Point Status If Less Than Double Precision             |
| 01     | 1B       | GTD      | Ds, Dc     |     R    | FPSR = (Ds > Dc?1:0)           | Set Floating Point Status If Greater Than Double Precision          |
| 01     | 1C       | LED      | Ds, Dc     |     R    | FPSR = (Ds <= Dc?1:0)          | Set Floating Point Status If Less or Equal Than Double Precision    |
| 01     | 1D       | GED      | Ds, Dc     |     R    | FPSR = (Ds >= Dc?1:0)          | Set Floating Point Status If Greater or Equal Than Double Precision |
| 02     |     X    | J        | Dest       |     J    | PC += E(Dest)                  | Jump; Dest is signed                                                |
| 03     |     X    | JAL      | Dest       |     J    | R31 = PC + 4; PC += E(Dest)    | Jump and Link; Dest is signed                                       |
| 04     |     X    | BEQZ     | Rs, Imm    |     I    | PC += (Rs == 0 ? E(Imm) : 0)   | Branch if equal to zero; Imm is signed                              |
| 05     |     X    | BNEZ     | Rs, Imm    |     I    | PC += (Rs != 0 ? E(Imm) : 0)   | Branch if not equal to zero; Imm is signed                          |
| 06     |     X    | BFPT     | Imm        |     I    | PC += (FPSR ? E(Imm) : 0)      | Branch if floating point status register is set; Imm is signed      |
| 07     |     X    | BFPF     | Imm        |     I    | PC += (!FPSR ? E(Imm) : 0)     | Branch if floating point status register is not set; Imm is signed  |
| 08     |     X    | ADDI     | Rd,Rs,Imm  |     I    | Rd = Rs + E(Imm)               | Add immediate; Imm is signed                                        |
| 09     |     X    | ADDUI    | Rd,Rs,Imm  |     I    | Rd = Rs + U(Imm)               | Add immediate; Imm is unsigned                                      |
| 0A     |     X    | SUBI     | Rd,Rs,Imm  |     I    | Rd = Rs - E(Imm)               | Subtract immediate; Imm is signed                                   |
| 0B     |     X    | SUBUI    | Rd,Rs,Imm  |     I    | Rd = Rs - U(Imm)               | Subtract immediate; Imm is unsigned                                 |
| 0C     |     X    | ANDI     | Rd,Rs,Imm  |     I    | Rd = Rs & Imm                  | Bitwise And immediate                                               |
| 0D     |     X    | ORI      | Rd,Rs,Imm  |     I    | Rd = Rs | Imm                  | Bitwise Or Imm                                                      |
| 0E     |     X    | XORI     | Rd,Rs,Imm  |     I    | Rd = Rs ^ Imm                  | Bitwise Exclusive Or immediate                                      |
| 0F     |     X    | LHI      | Rd, Imm    |     I    | Rd = E(Imm) << 16              | Load High Immediate; Zero lower half                                |
| 10     |     X    | RFE      |            |     J    | Recover from Saved State       | Return from exception / Return from Trap                            |
| 11     |     X    | TRAP     | Imm        |     J    | Save State; Syscall Imm        | Trap/Syscall; Wait until pipeline is cleared before called          |
| 12     |     X    | JR       | Rs         |     I    | PC = Rs                        | Jump Register                                                       |
| 13     |     X    | JALR     | Rs         |     I    | R31 = PC + 4; PC = Rs          | Jump and Link Register                                              |
| 14     |     X    | SLLI     | Rd,Rs,Imm  |     I    | Rd = Rs << U(Imm&0x1f)         | Shift Left Logical Immediate                                        |
| 16     |     X    | SRLI     | Rd,Rs,Imm  |     I    | Rd = U(Rs) >> U(Imm&0x1f)      | Shift Right Logical Immediate                                       |
| 17     |     X    | SRAI     | Rd,Rs,Imm  |     I    | Rd = E(Rs) >> U(Imm&0x1f)      | Shift Right Arithmetic Immediate                                    |
| 18     |     X    | SEQI     | Rd,Rs,Imm  |     I    | Rd = (Rs==E(Imm)?1:0)          | Set Equal Immediate                                                 |
| 19     |     X    | SNEI     | Rd,Rs,Imm  |     I    | Rd = (Rs != E(Imm)?1:0)        | Set Not Equal Immediate                                             |
| 1A     |     X    | SLTI     | Rd,Rs,Imm  |     I    | Rd = (Rs < E(Imm)?1:0)         | Set Less Than Immediate ; Imm is signed                             |
| 1B     |     X    | SGTI     | Rd,Rs,Imm  |     I    | Rd = (Rs > E(Imm)?1:0)         | Set Greater Than Immediate ; Imm is signed                          |
| 1C     |     X    | SLEI     | Rd,Rs,Imm  |     I    | Rd = (Rs <= E(Imm)?1:0)        | Set Less Than Or Equal Immediate ; Imm is signed                    |
| 1D     |     X    | SGEI     | Rd,Rs,Imm  |     I    | Rd = (Rs >= E(Imm)?1:0)        | Set Greater Than Or Equal Immediate ; Imm is signed                 |
| 20     |     X    | LB       | Rd,Addr    |     I    | Rd = E(MEM[Addr]&0xFF)         | Load Byte; Load byte will be signed                                 |
| 21     |     X    | LH       | Rd,Addr    |     I    | Rd = E(MEM[Addr]&0xFFFF)       | Load Half Word; Load half word will be signed                       |
| 23     |     X    | LW       | Rd,Addr    |     I    | Rd = MEM[Addr]                 | Load Word                                                           |
| 24     |     X    | LBU      | Rd,Addr    |     I    | Rd = U(MEM[Addr]&0xFF)         | Load Byte Unsigned; Load byte will be unsigned                      |
| 25     |     X    | LHU      | Rd,Addr    |     I    | Rd = U(MEM[Addr]&0xFFFF)       | Load Half Word; Load half word will be unsigned                     |
| 26     |     X    | LF       | Fd,Addr    |     I    | Fd = MEM[Addr]                 | Load Single Precision Floating Point                                |
| 27     |     X    | LD       | Dr,Addr    |     I    | Dr = (MEM[Addr]<<32)           | MEM[Addr+4]                                                         |
| 28     |     X    | SB       | Addr,Rd    |     I    | byte MEM[Addr]= Rd&0xFF        | Store Byte ; Uses Destination Register as Source                    |
| 29     |     X    | SH       | Addr,Rd    |     I    | halfword MEM[Addr]= Rd&0xFFFF  | Store Half Word  ; Uses Destination Register as Source              |
| 3B     |     X    | SW       | Addr,Rd    |     I    | MEM[Addr]= Rd                  | Store Word ; Uses Destination Register as Source                    |
| 3E     |     X    | SF       | Addr,Fd    |     I    | MEM[Addr]= Fd                  | Store Single Precision Floating Point ; Uses Destination as Source  |
| 3F     |     X    | SD       | Addr,Dr    |     I    | dword MEM[Addr:Addr+8] = Dr    | Store Double Precision Floating Point ; Uses Destination as Source  |

Opcode and Function encoding differs between implementations and papers, so just take this as a proposal based on https://www.csd.uoc.gr/~hy425/2002s/dlxmap.html

## Encodings

| Format |  LB    |  --------> | -------->   | -------->   |     MB      |
|--------|:------:|------------|-------------|-------------|-------------|
|        |  0 - 5 |   6 - 10   |   11 - 15   |   16 - 20   |   21 - 31   |
|    R   |    0   | Xs         | Xc          | Xd          | Function    |
|    I   | Opcode | Xs         | Xd          | Imm[16:20]  | Imm[21:31]  |
|    J   | Opcode | Dest[6:10] | Dest[11:15] | Dest[16:20] | Dest[21:31] |


## Example for Formats

    label:
    ORI R1, R2, #123
    SUB R1, R1, R1
    ADDI R3, R7, #-5 
    LW  R1, -4(R2) ; a comment
    SB  123(R0), R2
    BEQZ R4, skip
    J label
    skip:
    MOVI2F F2, R3 ; random floating point code
    MOVF2D D0, F2
    LTF F2, F0
    BFPF label

## References

- https://github.com/smetzlaff/openDLX/blob/master/src/openDLX/Decode.java
- https://www.csd.uoc.gr/~hy425/2002s/dlxmap.html
- https://www.csee.umbc.edu/courses/undergraduate/411/spring96/dlx.html
- http://ece628web.groups.et.byu.net/DLX/DLXinst.html
- http://cs.hadassah.ac.il/staff/martin/Adv_Architecture/slide02.pdf