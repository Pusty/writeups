arr = b'flag{??????????????????????????????}'
arr = [o for o in arr]

data191 = [0, 4129, 8258, 12387, 16516, 20645, 24774, 28903, 33032, 37161, 41290, 45419, 49548, 53677, 57806, 61935, 4657, 528, 12915, 8786, 21173, 17044, 29431, 25302, 37689, 33560, 45947, 41818, 54205, 50076, 62463, 58334, 9314, 13379, 1056, 5121, 25830, 29895, 17572, 21637, 42346, 46411, 34088, 38153, 58862, 62927, 50604, 54669, 13907, 9842, 5649, 1584, 30423, 26358, 22165, 18100, 46939, 42874, 38681, 34616, 63455, 59390, 55197, 51132, 18628, 22757, 26758, 30887, 2112, 6241, 10242, 14371, 51660, 55789, 59790, 63919, 35144, 39273, 43274, 47403, 23285, 19156, 31415, 27286, 6769, 2640, 14899, 10770, 56317, 52188, 64447, 60318, 39801, 35672, 47931, 43802, 27814, 31879, 19684, 23749, 11298, 15363, 3168, 7233, 60846, 64911, 52716, 56781, 44330, 48395, 36200, 40265, 32407, 28342, 24277, 20212, 15891, 11826, 7761, 3696, 65439, 61374, 57309, 53244, 48923, 44858, 40793, 36728, 37256, 33193, 45514, 41451, 53516, 49453, 61774, 57711, 4224, 161, 12482, 8419, 20484, 16421, 28742, 24679, 33721, 37784, 41979, 46042, 49981, 54044, 58239, 62302, 689, 4752, 8947, 13010, 16949, 21012, 25207, 29270, 46570, 42443, 38312, 34185, 62830, 58703, 54572, 50445, 13538, 9411, 5280, 1153, 29798, 25671, 21540, 17413, 42971, 47098, 34713, 38840, 59231, 63358, 50973, 55100, 9939, 14066, 1681, 5808, 26199, 30326, 17941, 22068, 55628, 51565, 63758, 59695, 39368, 35305, 47498, 43435, 22596, 18533, 30726, 26663, 6336, 2273, 14466, 10403, 52093, 56156, 60223, 64286, 35833, 39896, 43963, 48026, 19061, 23124, 27191, 31254, 2801, 6864, 10931, 14994, 64814, 60687, 56684, 52557, 48554, 44427, 40424, 36297, 31782, 27655, 23652, 19525, 15522, 11395, 7392, 3265, 61215, 65342, 53085, 57212, 44955, 49082, 36825, 40952, 28183, 32310, 20053, 24180, 11923, 16050, 3793, 7920]
def checksum(a, b):
    v0 = data191[a^0xff]
    v1 = data191[(((~v0)>>8)&0xff)^b]
    res = v1^((v0<<8)&0xff00)
    return res
    
def brute(arr, i):
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    #From addr 0x17d,  0x017e, 0x017f, 0x0180, 0x0181, 0x0182
    codes =   [0xb9fe, 0xe249, 0x5d06, 0xa9df, 0x362c, 0x08ff]
    code = codes[i]
    for c0 in charset:
        for c1 in charset:
            if checksum(ord(c0), ord(c1)) == code:
                return (ord(c0), ord(c1))
    return None
    
def applyRule10(arr, i):
    indexTable = [(6, 7), (0xa, 0xb), (0xe, 0xf), (0x13, 0x14), (0xd, 0x11), (0x1c, 0x1d)]
    indx0, indx1 = indexTable[i]
    a, b  = brute(arr, i)
    arr[indx0] = a
    arr[indx1] = b
    applyRule9(arr)
    
def applyRule9(arr):
    for i in range(len(arr)-1):
        if arr[i] == 0x7b: arr[i+1] = arr[i] ^ 15
        elif arr[i] == 0x31: arr[i+1] = arr[i] ^ 66
        elif arr[i] == 0x73: arr[i+1] = arr[i] ^ 44
        elif arr[i] == 0x75: arr[i+1] = arr[i] ^ 25
        elif arr[i] == 0x79: arr[i+1] = arr[i] ^ 38  
        elif arr[i] == 0x30: arr[i+1] = arr[i] ^ 66
        elif arr[i] == 0x65: arr[i+1] = arr[i] ^ 58
        elif arr[i] == 0x42: arr[i+1] = arr[i] ^ 58 
        elif arr[i] == 0x78: arr[i+1] = arr[i] ^ 28
        elif arr[i] == 0x64: arr[i+1] = arr[i] ^ 51
        elif arr[i] == 0x57: arr[i+1] = arr[i] ^ 111
        elif arr[i] == 0x38: arr[i+1] = arr[i] ^ 115  
        elif arr[i] == 0x4b: arr[i+1] = arr[i] ^ 54  
        
applyRule9(arr)

# There are 6 checks
for i in range(6):
    applyRule10(arr, i)
    
# Guessed from context
arr[26] = ord('e')
applyRule9(arr)

print(bytes(arr))