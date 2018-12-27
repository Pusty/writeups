import glob, os
from subprocess import check_output
from subprocess import Popen, PIPE, STDOUT


from operator import itemgetter

r = []
os.chdir("./FLEGGO")
for file in glob.glob("*.exe"):
    print(file)
    out = check_output(["strings", "-el",file])
    pw  = out.split("\n")[-2].strip()
    p = Popen([file], stdout=PIPE, stdin=PIPE, stderr=STDOUT)  
    out = p.communicate(input=pw)[0]
    result = out.split("\n")[-2].strip()
    print(result)
    r.append(result)
    
print(r)

data = []
for v in r:
    time = int(v.split(".png")[0].strip())
    value = v.split("=>")[1].strip()
    data.append((time,value))
    
data.sort(key=itemgetter(0))
for v in data:
    print(str(v[0])+": "+v[1])