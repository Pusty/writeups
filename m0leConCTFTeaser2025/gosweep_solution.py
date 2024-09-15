import requests
from pwn import *
from threading import Thread
import time

remoteUrl = "https://gosweep.challs.m0lecon.it/"

def dumpSecretPath(timestamp):
    io = gdb.debug(['./GoSweep'], api=True)
    io_gdb = io.gdb

    io_gdb.execute("b* 0x647e16") # set time name
    io_gdb.execute("b* 0x647e66") # dump name 
    io_gdb.continue_and_wait()
    io_gdb.execute("set $rax="+hex(timestamp))
    io_gdb.continue_and_wait()
    res = io_gdb.execute("x/s $rax", False, True).split(":")[1].strip().replace('"', "")
    io_gdb.continue_nowait()
    io_gdb.quit()
    io.kill()
    return res

def dumpSolution(seed, arenaSize, timestamp, endPoint):
    io = gdb.debug('./GoSweep', api=True)
    io_gdb = io.gdb

    def newBoard():
        time.sleep(1)
        url = "http://localhost:8080"
        x = requests.get(url+endPoint, json = {}, timeout=20)
        game = x.json()
        print("Local Response", game)

    io_gdb.execute("b* 0x647e16") # set time name
    if arenaSize == 20:
        io_gdb.execute("b* 0x643f20") # start 20x20
        io_gdb.execute("b* 0x6441c4") # stop 20x20
    else:
        io_gdb.execute("b* 0x644280") # start 50x50
        io_gdb.execute("b* 0x644524") # stop 50x50
    io_gdb.continue_and_wait()
    io_gdb.execute("set $rax="+hex(timestamp)) # set timestamp seed (for /secretpath)
    thread = Thread(target=newBoard)
    thread.start()
    io_gdb.continue_and_wait()
    print("Set seed")
    print("Before", io_gdb.execute("p/x $rax", False, True).strip())
    io_gdb.execute("set $rax="+hex(seed))
    print("After", io_gdb.execute("p/x $rax", False, True).strip())
    io_gdb.continue_and_wait()

    lstAddr = int(io_gdb.execute("p/x $rax", False, True).strip().split(" = ")[1], 16)
    print(hex(lstAddr))

    def dumpU64(addr):
        return int(io_gdb.execute("x/a "+hex(addr), False, True).strip().split(":")[1], 16)
        
    def dumpU64N(addr, n):
        out = io_gdb.execute("x/"+str(n)+"a "+hex(addr), False, True)
        values = []
        for line in out.split("\n"):
            if line.strip() == "": continue
            line = line.strip().split(":")[1].strip()
            for v in line.split("\t"):
                if v.strip() == "": continue
                values.append(int(v.strip(), 16))
        return values
    print(hex(lstAddr))

    dump = ""
    # Dump the board
    for row in range(arenaSize):
        offset = lstAddr+8*3*row
        # dump row array
        rowArray, v0, v1 = dumpU64(offset), dumpU64(offset+8), dumpU64(offset+16)
        values = dumpU64N(rowArray, 3*v0) # dump columns at once because individually this is too slow
        for col in range(v0):
            offsetR = 3*col
            bomb, num, revealed = values[offsetR], values[offsetR+1], values[offsetR+2]
            if bomb == 0: # format it to reveal all non-bomb fields at once
                dump += "&row="+str(row)+"&col="+str(col)
    io_gdb.continue_nowait()
    thread.join()
    io_gdb.quit()
    io.kill()
    return dump


# Retrieve secret timestamp by solving 20x20 game

x = requests.get(remoteUrl+"/new", json = {})
remoteGame = x.json()
print(remoteGame)
seed = int(remoteGame["seed"])

dump=dumpSolution(seed, 20, 0, "/new")
x = requests.post(remoteUrl+"/reveal?gameID="+remoteGame["gameID"]+dump)
# solution from 20x20 game
ts = int(x.json()["message"].split(": ")[1])

# get the secret path that is generated from the timestamp (this initiates a 50x50 game)
timestampPath = dumpSecretPath(ts)
print(timestampPath)

# Start 50x50 game on remote
x = requests.get(remoteUrl+timestampPath, json = {})
remoteGame = x.json()
print(remoteGame)
seed = int(remoteGame["seed"])

# Dump solution from binary using same seed, timestamp and path
dump=dumpSolution(seed, 50, ts, timestampPath)
x = requests.post(remoteUrl+"/reveal?gameID="+remoteGame["gameID"]+dump)
print(x.json()["message"]) # get flag