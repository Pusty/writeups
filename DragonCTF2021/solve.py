import binascii

tableF = [  #^ 0x5e
    0xad,
    0x6b,
    0x4b,
    0x58,
    0xfa,
    0x2a,
    0xb9,
    0xd6,
    0x6c,
    0x21,
    0x74,
    0xde,
    0xf8,
    0x5c,
    0xfc,
    0x13
]
tableG = [ # ^ 0xb7
    0xca,
    0xef,
    0xe5,
    0x39,
    0x7c,
    0x95,
    0x65,
    0x87,
    0x87,
    0x73,
    0x0A,
    0x17,
    0xbc,
    0x08,
    0x34,
    0x33
]

tableB={15: 118, 188: 101, 201: 221, 245: 230, 223: 158, 196: 28, 37: 63, 102: 51, 20: 250, 134: 68, 195: 46, 209: 62, 69: 110, 50: 35, 21: 89, 192: 186, 187: 234, 117: 157, 167: 92, 16: 202, 81: 209, 253: 84, 230: 142, 208: 112, 110: 159, 101: 77, 215: 14, 227: 17, 38: 247, 1: 124, 6: 111, 26: 162, 144: 96, 44: 113, 241: 161, 186: 244, 11: 43, 57: 18, 236: 206, 200: 232, 213: 3, 2: 119, 246: 66, 76: 41, 5: 107, 139: 61, 152: 70, 3: 123, 239: 223, 194: 37, 141: 93, 180: 141, 71: 160, 18: 201, 100: 67, 115: 143, 106: 2, 103: 133, 248: 65, 231: 148, 226: 152, 235: 233, 178: 55, 114: 64, 65: 131, 216: 97, 79: 132, 184: 108, 130: 19, 205: 189, 179: 109, 64: 9, 183: 169, 45: 216, 0: 99, 112: 81, 126: 243, 77: 227, 220: 134, 133: 151, 49: 199, 135: 23, 55: 154, 68: 27, 174: 228, 10: 103, 12: 254, 217: 53, 74: 214, 4: 242, 93: 76, 61: 39, 91: 57, 94: 88, 84: 32, 54: 5, 229: 217, 240: 140, 171: 98, 13: 215, 41: 165, 75: 179, 149: 42, 46: 49, 105: 249, 58: 128, 118: 56, 23: 240, 113: 163, 99: 251, 60: 235, 86: 177, 98: 170, 166: 36, 153: 238, 145: 129, 176: 231, 125: 255, 157: 94, 146: 79, 170: 172, 31: 192, 175: 121, 249: 153, 97: 239, 120: 188, 78: 47, 8: 48, 173: 149, 66: 44, 119: 245, 122: 218, 67: 26, 53: 150, 163: 10, 255: 22, 63: 117, 132: 95, 28: 156, 129: 12, 59: 226, 254: 187, 92: 74, 228: 105, 47: 21, 111: 168, 56: 7, 182: 78, 83: 237, 202: 116, 233: 30, 32: 183, 197: 166, 85: 252, 212: 72, 108: 80, 140: 100, 52: 24, 193: 120, 70: 90, 7: 197, 238: 40, 24: 173, 138: 126, 62: 178, 43: 241, 169: 211, 210: 181, 251: 15, 128: 205, 131: 236, 88: 106, 127: 210, 185: 86, 121: 182, 156: 222, 222: 29, 73: 59, 72: 82, 164: 73, 25: 212, 165: 6, 17: 130, 80: 83, 33: 253, 159: 219, 214: 246, 39: 204, 225: 248, 250: 45, 35: 38, 90: 190, 9: 1, 30: 114, 168: 194, 22: 71, 124: 16, 252: 176, 199: 198, 51: 195, 109: 60, 219: 185, 87: 91, 34: 147, 232: 155, 154: 184, 177: 200, 36: 54, 95: 207, 242: 137, 162: 58, 158: 11, 42: 229, 207: 138, 104: 69, 190: 174, 48: 4, 143: 115, 211: 102, 189: 122, 82: 0, 123: 33, 206: 139, 137: 167, 107: 127, 221: 193, 198: 180, 243: 13, 204: 75, 234: 135, 150: 144, 40: 52, 96: 208, 14: 171, 160: 224, 151: 136, 89: 203, 181: 213, 218: 87, 161: 50, 224: 225, 237: 85, 147: 220, 244: 191, 203: 31, 29: 164, 27: 175, 247: 104, 148: 34, 155: 20, 116: 146, 142: 25, 191: 8, 19: 125, 136: 196, 172: 145}

NFT_PAYLOAD_TRANSPORT_HEADER = [0]*76

CORRECT_OUTPUT = b'2I\x1dU\xad\xe6\xc6\xb3wG\xf5~\xd4X\xc9\x05r\x8f\x9aGD\xcav\xdb6\xf9\x90x6\x10\x80\xd5'

for i in range(len(NFT_PAYLOAD_TRANSPORT_HEADER)):
    NFT_PAYLOAD_TRANSPORT_HEADER[i] = ord('A')
    
NFT_PAYLOAD_TRANSPORT_HEADER = NFT_PAYLOAD_TRANSPORT_HEADER[:28]+list(b'\x88\xd8\x88K\xe0V\xcf\xf3')+NFT_PAYLOAD_TRANSPORT_HEADER[36:]

def apply(inp, NUMGENINC):
    r1 = inp&0xFF
    r3 = r1 ^ tableF[NUMGENINC%16]
    r3 = tableB[r3]
    r4 = r3 ^ tableG[NUMGENINC%16]
    r1 = tableB[r4] 
    return r1&0xFF

NUMGENINC = 0
for i in range(32):
    for x in range(0x100):
        o = apply(x, NUMGENINC)
        if o == CORRECT_OUTPUT[i]:
            NFT_PAYLOAD_TRANSPORT_HEADER[44+i] = x
            break
    NUMGENINC += 1
    
print("HEADER: ",binascii.hexlify(bytes(NFT_PAYLOAD_TRANSPORT_HEADER[28:28+8])))
print("INPUT: ",binascii.hexlify(bytes(NFT_PAYLOAD_TRANSPORT_HEADER[44:76])))

# verify
NUMGENINC = 0
for i in range(32):
    NFT_PAYLOAD_TRANSPORT_HEADER[44+i] = apply(NFT_PAYLOAD_TRANSPORT_HEADER[44+i], NUMGENINC)
    NUMGENINC += 1
    
reg1 = NFT_PAYLOAD_TRANSPORT_HEADER[44:60] # read header
reg2 = NFT_PAYLOAD_TRANSPORT_HEADER[60:76]

#reg3 = [0]*16
#NFT_PAYLOAD_TRANSPORT_HEADER = NFT_PAYLOAD_TRANSPORT_HEADER[:44]+reg3+NFT_PAYLOAD_TRANSPORT_HEADER[60:] # zero header
#NFT_PAYLOAD_TRANSPORT_HEADER = NFT_PAYLOAD_TRANSPORT_HEADER[:60]+reg3+NFT_PAYLOAD_TRANSPORT_HEADER[76:]


print(bytes(NFT_PAYLOAD_TRANSPORT_HEADER[28:36]) == b'\x88\xd8\x88K\xe0V\xcf\xf3')
print(bytes(reg1) == b'2I\x1dU\xad\xe6\xc6\xb3wG\xf5~\xd4X\xc9\x05')
print(bytes(reg2) == b'r\x8f\x9aGD\xcav\xdb6\xf9\x90x6\x10\x80\xd5')

