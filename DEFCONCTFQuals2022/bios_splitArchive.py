import os
import subprocess

f = open("bios-nautilus.bin", "rb")
data = f.read()
f.close()

parts = data.split(b"LARCHIVE")

for part in parts[1:]:
    o = open("dump.bin" , "wb")
    o.write(b"LARCHIVE"+part)
    o.close()
    result = subprocess.check_output("bash -c './coreboot/util/cbfstool/cbfstool dump.bin print'", shell=True)
    name = result.split(b"\n")[2].split(b" ")[0].decode("utf-8")
    result = subprocess.check_output("bash -c './coreboot/util/cbfstool/cbfstool dump.bin extract -f dump/"+name+" -n "+name+"'", shell=True)
    print(name)