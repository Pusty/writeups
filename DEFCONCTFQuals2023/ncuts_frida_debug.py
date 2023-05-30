import frida
import os
import string
import time

device = frida.get_local_device()

pid = 0
output = None



def run(name, inp, last=None):
    global pid, output
    
    print("Binary '%s'" % name)
    output = None

    fileSizeMap = {
        55448: 0,
        51352: 1,
        71832: 2,
    }
    
    typ = fileSizeMap[os.path.getsize('./output/%s' % name)] 
    
    pid = device.spawn(['./output/%s' % name], stdio='pipe')
    session = frida.attach(pid)

    # offset of of the vmbody depending on the type of binary
    baseAddressMap = {
        0: "0x5f20",
        1: "0x4c70",
        2: "0xa920"
    }
    
    content = """
    var base = Module.getBaseAddress("%s");

    Interceptor.attach(base.add(%s), {
        onEnter: function (args) {
            this.mem = args[0]; // this is the memory argument
        },
        onLeave: function (ret) {
            send("vmmem", this.mem.readByteArray(0xfa000));
        }
    });
    """ % (name, baseAddressMap[typ])

    
    def on_message(message, data):
        global output
        if not 'payload' in message:
            print(message)
        else:
            if message['payload'] == "vmmem":
                start = 0x00F9F70
                for i in range(9):
                    line = "[%08X] " % (start+i*16)
                    for j in range(16):
                        line += ("%02X " % data[start+i*16+j])
                    line += " | "
                    for j in range(16):
                        if chr(data[start+i*16+j]) in (string.digits+string.ascii_letters+string.punctuation):
                            line += ("%c" % data[start+i*16+j])
                        else:
                            line += " "
                    print(line)
                output = data
            else:
                print(message, data)

    script = session.create_script(content)
    script.on('message', on_message)
    script.load()
    device.resume(pid)


    if last != None:
        device.input(pid, last)
    
    device.input(pid, inp)
    print("Input: ", inp)
    
    
    while output == None:
        time.sleep(0.5)
        
    return output


solution0 = bytes.fromhex('424d38d302000000')
solution1 = bytes.fromhex('0000360000002800')

#run('0', b"AAAAAAAA", None)
#run('0', b"BBBBBBBB", None)
#run('0', b"AABBCCDD", None)

#run('1', b"AAAAAAAA", solution0)
#run('1', b"BBBBBBBB", solution0)

run('2', b"AAAAAAAA", solution1)
run('2', b"\x01\x02\x04\x08\x10\x20\x40\x80", solution1)