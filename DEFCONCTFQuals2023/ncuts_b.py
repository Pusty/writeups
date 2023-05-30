import frida
import time
import math
import os

import findcandidate
import flagcombiner


device = frida.get_local_device()

typ = -1
pid = 0
output = None

def unbitshuffle(encInput, encFlag):
    shuffle = [int(math.log(int(s), 2)) for s in encInput]

    reshuffled = []
    for i in range(len(encFlag)):
        v = 0
        for j in range(8):
            v = v | (((encFlag[i]>>shuffle[j])&1)<<j)
        reshuffled.append(v)
    return bytes(reshuffled)
     

def run(name, last=None):
    global typ, pid, output
    
    output = None

    fileSizeMap = {
        55448: 0,
        51352: 1,
        71832: 2,
    }
    
    size = os.path.getsize('./output/%s' % name)
    typ = -1
    typ = fileSizeMap[size] 
    
    pid = device.spawn(['./output/%s' % name], stdio='pipe')
    session = frida.attach(pid)

    # address of vmbody
    baseAddressMap = {
        0: "0x5f20",
        1: "0x4c70",
        2: "0xa920"
    }
    
    content = """
    var base = Module.getBaseAddress("%s");
    Interceptor.attach(base.add(%s), {
        onEnter: function (args) {
            this.mem = args[0];
        },
        onLeave: function (ret) {
            send("vmmem", this.mem.readByteArray(0xfa000));
        }
    });
    """ % (name, baseAddressMap[typ])

   
    """
    55KB -  apply offset on all?#
    51KB -  apply 8 byte xor key
    71kB -  bitshuffle
    """
    def on_message(message, data):
        global typ, output
        if not 'payload' in message:
            print(message)
        else:
            if message['payload'] == "vmmem":
                if output != None: return
                
                # Solve Type 0
                if typ == 0:
                    encFlag = data[1023956:][:8][::-1]
                    encInput = data[1023948:][:8][::-1]
                    offset = encInput[0]-ord('A')
                    output = bytes([(b-offset)&0xff for b in encFlag])

                # Solve Type 1
                elif typ == 1:
                    encFlag = data[1023972:][:8][::-1]
                    encInput = data[1023980:][:8][::-1]
                    hexKey = bytes([encInput[i]^ord('A') for i in range(8)])
                    output = bytes([hexKey[i]^encFlag[i] for i in range(8)])
                    
                # Solve Type 2
                elif typ == 2:
                    encFlag = data[1023979:][:8][::-1]
                    encInput = data[1023971:][:8][::-1]
                    output = unbitshuffle(encInput, encFlag)
                
            else:
                print(message, data)

    script = session.create_script(content)
    script.on('message', on_message)
    script.load()
    device.resume(pid)

    if last != None:
        device.input(pid, last)
    
    if typ == 0 or typ == 1:
        device.input(pid, b"A"*8)
    elif typ == 2:
        device.input(pid, bytes([1<<i for i in range(8)]))

    while output == None:
        time.sleep(0.2)

    session.detach()

    return output

alreadyExplored = []
exploreStack = []

# needed if you need to restart the process
starts = flagcombiner.findEntries()
for frm, key in starts:
    alreadyExplored.append(frm)
    if key == "None": continue
    key = bytes.fromhex(key)
    paths = findcandidate.findCandidate(key)
    for path in paths:
        if flagcombiner.already(path): continue
        exploreStack.append((path, frm, key))

# find all entry points as start points
starts = findcandidate.findEntrypoint()
for start in starts:
    if start in alreadyExplored: continue
    exploreStack.append((start, None, None))

while len(exploreStack) > 0:
    name, frm, key = exploreStack.pop()
    if len(name) < 5: continue # ignore the first "0"-"2227" binaries because we already have them - uncomment this if you want to solve all at the same time
    if name in alreadyExplored: continue
    
    res = run(name, key)
    alreadyExplored.append(name)
    
    print(len(alreadyExplored), frm, "=>", name, ";", (None if key == None else key.hex()), "=>", res.hex(), flush=True)
    
    paths = findcandidate.findCandidate(res)
    for path in paths:
        exploreStack.append((path, name, res))