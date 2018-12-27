import os
import shutil


currentFolder = "" #folder this script is in
sourceFolder  = "" #folder containing original of magic as it selfmodifes itself (to reset)

try:
    os.remove(currentFolder+"/magic") 
except Exception:
    pass
shutil.copy2(sourceFolder+'/magic', currentFolder+'/magic')

try:
    os.mkdir(currentFolder+"/flags") 
except Exception:
    pass

currentIndex = 0
os.system('gdb ./magic -ex "py currentIndex = '+str(currentIndex)+'" -ex "source magicUnicorn.py" -ex "source magicUnicorn.py"  -ex "quit"')