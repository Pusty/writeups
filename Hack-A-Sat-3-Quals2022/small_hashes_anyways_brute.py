import subprocess, os
import string

customenv = os.environ.copy()

# microblaze-linux in user home folder
customenv["QEMU_LD_PREFIX"] = os.path.expanduser("~")+"/microblaze-linux/"
customenv["LD_LIBRARY_PATH"] = os.path.expanduser("~")+"/microblaze-linux/lib/"

# binary tells us that it wants 112 bytes input
inp = [0x20]*112

for curIndex in range(112):
    # bruteforce for all ascii characters that one would expect in the flag
    for c in string.ascii_letters + string.digits + string.punctuation:
        inp[curIndex] = ord(c)
        # run in qemu
        proc = subprocess.Popen(["qemu-microblaze", "./small_hashes_anyways"], env=customenv, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        
        # give it the hash
        proc.stdin.write(bytes(inp)+b"\n")
        proc.stdin.close()
        while proc.returncode is None:
            proc.poll()
            
        # small hashes anyways:
        # mismatch 1 wanted 1993550816 got 3916222277
        stin = proc.stdout.read().decode("utf-8")
        res = stin.split("\n")[1].split(" ")
        
        # if it's a digit then the hash was wrong, otherwise the input was correct
        if res[1].isdigit():
            wrongIndex = int(res[1])-1
        else:
            print(stin)
            break
        
        # found correct character
        if wrongIndex != curIndex:
            break

    print(bytes(inp[:(curIndex+1)]).decode("utf-8"))