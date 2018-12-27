data = [15, 87, 97, 119, 11, 250, 181, 209, 129, 153, 172, 167,144, 88, 26, 82, 12, 160, 8, 45, 237, 213, 109, 231,224, 242, 188, 233, 242]
data2 = []
data2.append(data[0])
for cryptoIndex in range(1,len(data)):
        data2.append(data[cryptoIndex]^data[cryptoIndex-1])
print data2