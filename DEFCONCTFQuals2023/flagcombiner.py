flagMap = {}

def initDB(fn):
    try:
        log = open(fn, "r")
        for line in log:
            idd, _, frm, to, _, key, _, pwd = line.split(" ")
            pwd = pwd.strip()
            flagMap[to] = (key, pwd)
        
        log.close()
    except Exception as e:
        print(e)
    
initDB("passwords-b-dump.txt")

# frm, key pairs - continue from
def findEntries():
    l = []
    for key, value in flagMap.items():
        l.append((key, value[1]))
    return l

# used to reduce redundancy during the search
def already(n):
    return n in flagMap
    
def getID(name):
    import pwn
    pwn.context.log_level = 'warn'
    p = pwn.process('./output/'+name)
    key, pwd = flagMap[name]
    
    # send decrypt password
    if key != "None":
        p.send(bytes.fromhex(key))
        p.recvline()
        
    # send password
    p.send(bytes.fromhex(pwd))
    
    v = 0
    try:
        v = int(p.recvline().strip().split(b"ID: ")[1])
    except Exception as e:
        print("[!] "+name+" could not be parsed correctly") 
        v = 0
    p.close()
    return v
    
def makeImage():
    imageMap = {}
    
    # part (b) binaries
    i = 0
    for key, value in flagMap.items():
        if i % 1000 == 0:
            print(str(i)+" binaries processed")
        idd = getID(key)
        imageMap[idd] = bytes.fromhex(value[1])
        i = i + 1
        
    # backup (b) binary mapping
    log = open("passwords-b.txt", "w")
    for key, value in imageMap.items(): 
        log.write(str(key)+" "+value.hex()+"\n")
    log.close()
    
    # solution from (a)
    log = open("passwords-a.txt", "r")
    for line in log:
        idd, pwd = line.split(" ")
        pwd = bytes.fromhex(pwd.strip())
        idd = int(idd)
        imageMap[idd] = pwd
    log.close()
    
    # check for missing index stuff
    for i in range(len(imageMap)):
        if not (i in imageMap):
            print("[!] "+str(i)+" is missing in the map")

    
    # write all bytes in order
    img = open("output2.bmp", "wb")
    for i in range(len(imageMap)):
        if not (i in imageMap): 
            img.write(b"\x00"*8)
        else:
            img.write(imageMap[i]) 
    img.close()