# uncompyle6 version 3.3.5
# Python bytecode 3.6 (3379)
# Decompiled from: Python 3.6.8 (default, Oct  7 2019, 12:59:55) 
# [GCC 8.3.0]
# Embedded file name: circ.py
# Compiled at: 2019-12-13 19:29:55
# Size of source mod 2**32: 5146 bytes

def func_0(vmCode):
    instructionPointer = 0
    register = [0] * 2 ** (2 * 2)
    memory = [0] * 100
    stack = []
    
    subKey = 0
    xorKey = 0
    while vmCode[instructionPointer][0] != 'sym0':
        instruction = vmCode[instructionPointer][0].lower()
        instructionData = vmCode[instructionPointer][1:]
        if instruction == 'sym1':
            register[instructionData[0]] = register[instructionData[1]] + register[instructionData[2]]
        elif instruction == 'sym2':
            register[instructionData[0]] = register[instructionData[1]] ^ register[instructionData[2]]
        elif instruction == 'sym3':
            register[instructionData[0]] = register[instructionData[1]] - register[instructionData[2]]
        elif instruction == 'sym4':
            register[instructionData[0]] = register[instructionData[1]] * register[instructionData[2]]
        elif instruction == 'sym5':
            register[instructionData[0]] = register[instructionData[1]] / register[instructionData[2]]
        elif instruction == 'sym6':
            register[instructionData[0]] = register[instructionData[1]] & register[instructionData[2]]
        elif instruction == 'sym7':
            register[instructionData[0]] = register[instructionData[1]] | register[instructionData[2]]
        elif instruction == 'sym8':
            register[instructionData[0]] = register[instructionData[0]]
        elif instruction == 'sym9':
            register[instructionData[0]] = register[instructionData[1]]
        elif instruction == 'sym10':
            register[instructionData[0]] = instructionData[1]
        elif instruction == 'sym11':
            memory[instructionData[0]] = register[instructionData[1]]
        elif instruction == 'sym12':
            register[instructionData[0]] = memory[instructionData[1]]
            print(register[instructionData[0]]) # load input again
        elif instruction == 'sym13':
            register[instructionData[0]] = 0
        elif instruction == 'sym14':
            memory[instructionData[0]] = 0
        elif instruction == 'sym15':
            register[instructionData[0]] = input(register[instructionData[1]])
        elif instruction == 'sym16':
            memory[instructionData[0]] = input(register[instructionData[1]])
        elif instruction == 'sym17':
            print(register[instructionData[0]])
        elif instruction == 'sym18':
            print(memory[instructionData[0]])
        elif instruction == 'sym19':
            instructionPointer = register[instructionData[0]]
        elif instruction == 'sym20':
            instructionPointer = memory[instructionData[0]]
        elif instruction == 'sym21':
            instructionPointer = stack.pop()
        elif instruction == 'sym22':
            if register[instructionData[1]] > register[instructionData[2]]:
                instructionPointer = instructionData[0]
                stack.append(instructionPointer)
                continue
        elif instruction == 'sym23':
            print(register[instructionData[0]]) # input
            print(register[instructionData[1]]) # compare
            
            tmp = ""
            for i in range(len(register[instructionData[1]])):
                tmp += chr(((ord(register[instructionData[1]][i])+subKey)&0xFF)^xorKey)
            print(tmp) #decrypted
            print(register[instructionData[2]]) # dst
            register[7] = 0
            for i in range(len(register[instructionData[0]])):
                if register[instructionData[0]] != register[instructionData[1]]:
                    register[7] = 1
                    instructionPointer = register[instructionData[2]]
                    stack.append(instructionPointer)
        elif instruction == 'sym24':
            unk_0 = ''
            print("XOR KEY: "+hex(register[instructionData[1]]))
            xorKey = register[instructionData[1]]
            for i in range(len(register[instructionData[0]])):
                unk_0 += chr(ord(register[instructionData[0]][i]) ^ register[instructionData[1]])
            register[instructionData[0]] = unk_0
        elif instruction == 'sym25':
            unk_0 = ''
            print("SUB KEY: "+hex(register[instructionData[1]]))
            subKey = register[instructionData[1]]
            for i in range(len(register[instructionData[0]])):
                unk_0 += chr(ord(register[instructionData[0]][i]) - register[instructionData[1]])
            register[instructionData[0]] = unk_0
        elif instruction == 'sym26':
            if register[instructionData[1]] > register[instructionData[2]]:
                instructionPointer = register[instructionData[0]]
                stack.append(instructionPointer)
                continue
        elif instruction == 'sym27':
            if register[instructionData[1]] > register[instructionData[2]]:
                instructionPointer = memory[instructionData[0]]
                stack.append(instructionPointer)
                continue
        elif instruction == 'sym28':
            if register[instructionData[1]] == register[instructionData[2]]:
                instructionPointer = instructionData[0]
                stack.append(instructionPointer)
                continue
        elif instruction == 'sym29':
            if register[instructionData[1]] == register[instructionData[2]]:
                instructionPointer = register[instructionData[0]]
                stack.append(instructionPointer)
                continue
        elif instruction == 'sym30':
            if register[instructionData[1]] == register[instructionData[2]]:
                instructionPointer = memory[instructionData[0]]
                stack.append(instructionPointer)
                continue
        instructionPointer += 1

# reg0  = 'Authentication token: '
# reg0  = input(reg0)
# reg6  = gibberish array
# reg2  = 120
# reg4  = 15
# reg3  = 1
# reg2  = reg2 * reg3
# reg2  = reg2 + reg4
# NOP ? or reg0 = reg2
# reg3 = 0
# reg6 = sum(reg6)
# reg0 = 'Thanks.'
# reg1 = 'Authorizing access...'
# print(reg0)
# reg0 = memory[0]
# reg0 = sum(reg0^reg2)
# reg0 = sum(reg0-reg4)
# reg5 = 19

func_0([
 [
  'sym10', 0, 'Authentication token: '], 
 [
  'sym16', 0, 0],
 [
  'sym10', 6, 'á×äÓâæíäàßåÉÛãåäÉÖÓÉäàÓÉÖÓåäÉÓÚÕæïèäßÙÚÉÛÓäàÙÔÉÓâæÉàÓÚÕÓÒÙæäàÉäàßåÉßåÉäàÓÉÚÓáÉ·Ôâ×ÚÕÓÔÉ³ÚÕæïèäßÙÚÉÅä×ÚÔ×æÔÉ×Úïá×ïåÉßÉÔÙÚäÉæÓ×ÜÜïÉà×âÓÉ×ÉÑÙÙÔÉâßÔÉÖãäÉßÉæÓ×ÜÜïÉÓÚÞÙïÉäàßåÉåÙÚÑÉßÉàÙèÓÉïÙãÉáßÜÜÉÓÚÞÙïÉßäÉ×åáÓÜÜ\x97ÉïÙãäãÖÓ\x9aÕÙÛ\x99á×äÕà©â«³£ï²ÕÔÈ·±â¨ë'],
 [
  'sym10', 2, 2 ** (3 * 2 + 1) - 2 ** (2 + 1)],
 [
  'sym10', 4, 15],
 [
  'sym10', 3, 1],
 [
  'sym4', 2, 2, 3],
 [
  'sym1', 2, 2, 4],
 [
  'sym8', 0, 2],
 [
  'sym13', 3],
 [
  'sym24', 6, 3],
 [
  'sym10', 0, 'Thanks.'],
 [
  'sym10', 1, 'Authorizing access...'],
 [
  'sym17', 0],
 [
  'sym12', 0, 0],
 [
  'sym24', 0, 2],
 [
  'sym25', 0, 4],
 [
  'sym10', 5, 19],
 [
  'sym23', 0, 6, 5],
 [
  'sym17', 1],
 [
  'sym0'],
 [
  'sym10', 1, 'Access denied!'],
 [
  'sym17', 1],
 [
  'sym0']])
# okay decompiling 3nohtyp.pyc

# watevr{this_must_be_the_best_encryption_method_evr_henceforth_this_is_the_new_Advanced_Encryption_Standard_anyways_i_dont_really_have_a_good_vid_but_i_really_enjoy_this_song_i_hope_you_will_enjoy_it_aswell!_youtube.com/watch?v=E5yFcdPAGv0}
