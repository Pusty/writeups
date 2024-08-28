from capstone import *

import numpy as np


context_dtype =  np.dtype([
    ("P1Home"            , np.uint64  ,       ),
    ("P2Home"            , np.uint64  ,       ),
    ("P3Home"            , np.uint64  ,       ),
    ("P4Home"            , np.uint64  ,       ),
    ("P5Home"            , np.uint64  ,       ),
    ("P6Home"            , np.uint64  ,       ),
    ("ContextFlags"      , np.uint32  ,       ),
    ("MxCsr"             , np.uint32  ,       ),
    ("SegCs"             , np.uint16  ,       ),
    ("SegDs"             , np.uint16  ,       ),
    ("SegEs"             , np.uint16  ,       ),
    ("SegFs"             , np.uint16  ,       ),
    ("SegGs"             , np.uint16  ,       ),
    ("SegSs"             , np.uint16  ,       ),
    ("EFlags"            , np.uint32  ,       ),
    ("Dr0"               , np.uint64  ,       ),
    ("Dr1"               , np.uint64  ,       ),
    ("Dr2"               , np.uint64  ,       ),
    ("Dr3"               , np.uint64  ,       ),
    ("Dr6"               , np.uint64  ,       ),
    ("Dr7"               , np.uint64  ,       ),
    ("Rax"               , np.uint64  ,       ),
    ("Rcx"               , np.uint64  ,       ),
    ("Rdx"               , np.uint64  ,       ),
    ("Rbx"               , np.uint64  ,       ),
    ("Rsp"               , np.uint64  ,       ),
    ("Rbp"               , np.uint64  ,       ),
    ("Rsi"               , np.uint64  ,       ),
    ("Rdi"               , np.uint64  ,       ),
    ("R8"                , np.uint64  ,       ),
    ("R9"                , np.uint64  ,       ),
    ("R10"               , np.uint64  ,       ),
    ("R11"               , np.uint64  ,       ),
    ("R12"               , np.uint64  ,       ),
    ("R13"               , np.uint64  ,       ),
    ("R14"               , np.uint64  ,       ),
    ("R15"               , np.uint64  ,       ),
    ("Rip"               , np.uint64  ,       ),
    ("D"                 , np.uint64  ,     (32,) ),
    ("VectorRegister"    , np.uint64  ,     (26*2,) ),
    ("VectorControl"     , np.uint64   ,     ),
    ("DebugControl"      , np.uint64   ,     ),
    ("LastBranchToRip"   , np.uint64   ,     ),
    ("LastBranchFromRip" , np.uint64   ,     ),
    ("LastExceptionToRip" , np.uint64   ,     ),
    ("LastExceptionFromRip" , np.uint64   ,     ),
])


# The challenge binary
f = open("dist-22621.exe", "rb")
FILE_DATA = f.read()
f.close()

# Hardcoded offsets from the binary  (adjust for different builds)
CODE = FILE_DATA[:0x495a26][0x1000:] # base address 0x401000
DATA = FILE_DATA[0x496000:]         # base address 0xA00000

TABLE = {}
# https://github.com/hfiref0x/SyscallTables/blob/master/Compiled/Composition/X86_64/NT10/ntos/
# ntos syscall number to name mapping for the binary
f = open("nt_22631.txt", "r")
lines = f.read().split("\n")
f.close()


for line in lines[:-1]:
    name, nr = line.split("\t")
    TABLE[int(nr)] = name


regs = {}

md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(CODE, 0x401000):
    if i.mnemonic == "mov":
        reg, val = i.op_str.split(", ")
        if val in regs:
            regs[reg] = regs[val]
        else:
            regs[reg] = val
    elif i.mnemonic == "movabs":
        reg, val = i.op_str.split(", ")
        regs[reg] = val
    elif i.mnemonic == "syscall":
        function = TABLE[int(regs["rax"], 16)&0xfff]
        
        values = []
        if "r10" in regs:
            values.append(regs["r10"])
        if "rdx" in regs:
            values.append(regs["rdx"])
        if "r8" in regs:
            values.append(regs["r8"])
        if "r9" in regs:
            values.append(regs["r9"])
        if "rsp" in regs:
            offset = int(regs["rsp"], 16) - 0xA00000
            for j in range(5, 16): # 1 filler, 4 shadow space
                values.append(hex(int.from_bytes(DATA[offset+j*8:][:8], byteorder='little')))
                
        
        formated = {}
        args = []
        optional = []
        
        if function == "NtWriteFile":
            args = ["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "Buffer", "Length", "ByteOffset", "Key"]
            optional = ["Event", "ApcRoutine", "ApcContext", "ByteOffset", "Key"]
        
        if function == "NtReadFile":
            args = ["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "Buffer", "Length", "ByteOffset", "Key"]
            optional = ["Event", "ApcRoutine", "ApcContext", "ByteOffset", "Key"]
        
        if function == "NtCreateIoCompletion":
            args = ["IoCompletionHandle", "DesiredAccess", "ObjectAttributes", "NumberOfConcurrentThreads"]
            optional = ["ObjectAttributes"]
            
        if function == "NtCreateWorkerFactory":
            args = ["WorkerFactoryHandleReturn", "DesiredAccess", "ObjectAttributes", "CompletionPortHandle", "WorkerProcessHandle", "StartRoutine", "StartParameter", "MaxThreadCount", "StackReserve", "StackCommit"]
            optional = ["ObjectAttributes", "StartParameter", "MaxThreadCount", "StackReserve", "StackCommit"]
            
        if function == "NtReadVirtualMemory":
            args = ["ProcessHandle", "BaseAddress", "Buffer", "NumberOfBytesToRead", "NumberOfBytesReaded"]
            optional = ["NumberOfBytesReaded"]
       
        if function == "NtWriteVirtualMemory":
            args = ["ProcessHandle", "BaseAddress", "Buffer", "NumberOfBytesToWrite", "NumberOfBytesWritten"]
            optional = ["NumberOfBytesWritten"]
       
        if function == "NtContinue":
            args = ["ThreadContext", "RaiseAlert"]
            optional = []
       
        if function == "NtContinueEx":
            args = ["ContextRecord", "ContinueArgument"]
            optional = []
          
        if function == "NtSetInformationWorkerFactory":
            args = ["WorkerFactoryHandle", "WorkerFactoryInformationClass", "WorkerFactoryInformation", "WorkerFactoryInformationLength"]
            optional = []
     
        if function == "NtQueryInformationWorkerFactory":
            args = ["WorkerFactoryHandle", "WorkerFactoryInformationClass", "WorkerFactoryInformation", "WorkerFactoryInformationLength", "ReturnLength"]
            optional = ["ReturnLength"]
        
        if function == "NtTerminateProcess":
            args = ["ProcessHandle", "ExitStatus"]
            optional = ["ProcessHandle"]
        
        
        if function == "NtCreateSemaphore":
            args = ["SemaphoreHandle", "DesiredAccess", "ObjectAttributes", "InitialCount", "MaximumCount"]
            optional = ["ObjectAttributes"]

        for j in range(len(args)):
            if args[j] in optional and values[j] == "0x0":
                continue
            formated[args[j]] = values[j]
            
        if "WorkerFactoryInformationClass" in formated:
            if formated["WorkerFactoryInformationClass"] == '7':
                formated["WorkerFactoryInformationClass"] = "WorkerFactoryBasicInformation"
            elif formated["WorkerFactoryInformationClass"] == '3':
                formated["WorkerFactoryInformationClass"] = "WorkerFactoryBindingCount"
            
        if function == "NtContinue" or function == "NtContinueEx":
        
            if function == "NtContinue":
                print("@ ", formated["ThreadContext"])
                addr = int(formated["ThreadContext"], 16) - 0xA00000
            elif function == "NtContinueEx":
                print("@ ", formated["ContextRecord"])
                addr = int(formated["ContextRecord"], 16) - 0xA00000
                
            cS  = np.frombuffer(DATA[addr:], dtype=context_dtype, count=1)[0]
            for name in context_dtype.names:
                if cS["ContextFlags"] == 0x100001 and (name == "Rsp" or name == "Rip" or name == "EFlags"):
                    print(name, hex(cS[name]))
                elif cS["ContextFlags"] != 0x100001:
                    for name in context_dtype.names:
                        print(name, hex(cS[name]))
        
        if len(args) == 0:
            print("Unknown function: ", function)
        
        print(hex(i.address), function, formated)
        regs = {}
        regs["rax"] = "return of "+function
    else:
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    


