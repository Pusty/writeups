# Crack Me

    Developed for SekaiCTF 2022 but never got a chance to release it. Can you log in and claim the flag?

Crack Me is an android application that asks for a email and password.

## Solution

When opening the app we are greeting with a login screen:

![](img/login.png)

Inspecting the internals of the app with jadx shows us in `com.SekaiCTF.CrackMe.MainApplication` that we are dealing with a ReactNative application.
Time to look for the JavaScript... which we can find in the `assets/index.android.bundle` file.

It is initially unreadable but just running it through a unminify program is enough to understand the internals.

Searching for the string "admin" we get the most interesting code:

```javascript
t.setState({
    verifying: !0
});
var n = (0, k.initializeApp)(T.default),
    o = (0, A.getDatabase)(n);
"admin@sekai.team" !== t.state.email || !1 === e.validatePassword(t.state.password) ? console.log("Not an admin account.") : console.log("You are an admin...This could be useful.");
var s = (0, M.getAuth)(n);
(0, M.signInWithEmailAndPassword)(s, t.state.email, t.state.password).then(function(e) {
    t.setState({
        verifying: !1
    });
    var n = (0, A.ref)(o, "users/" + e.user.uid + '/flag');
    (0, A.onValue)(n, function() {
        t.setState({
            verifying: !1
        }), t.setState({
            errorTitle: "Hello Admin",
            errorMessage: "Keep digging, you're almost there!"
        }), t.AlertPro.open()
    })
}).catch(function(e) {   [...]   })
```

So the admin email is `admin@sekai.team`. Following the password validation:

```javascript
e.validatePassword = function(e) {
                if (17 !== e.length) return !1;
                var t = R.default.enc.Utf8.parse(b.default.KEY),
                    n = R.default.enc.Utf8.parse(b.default.IV);
                return "03afaa672ff078c63d5bdb0ea08be12b09ea53ea822cd2acef36da5b279b9524" === R.default.AES.encrypt(e, t, {
                    iv: n
                }).ciphertext.toString(R.default.enc.Hex)
}
```

After searching for the constants used here:

```javascript
var _ = {
    LOGIN: "LOGIN",
    EMAIL_PLACEHOLDER: "user@sekai.team",
    PASSWORD_PLACEHOLDER: "password",
    BEGIN: "CRACKME",
    SIGNUP: "SIGN UP",
    LOGOUT: "LOGOUT",
    KEY: "react_native_expo_version_47.0.0",
    IV: "__sekaictf2023__"
};
```

Decrypting the password gives us `s3cr3t_SEKAI_P@ss`

![](img/appdec.png)

Entering these credentials gives us a popup with `Hello Admin` `Keep digging, you're almost there!`.

What we need to do is read out the flag value ourself with the credentials from the javascript file:

```python
import json
import pyrebase

config = {
  "apiKey": "AIzaSyCR2Al5_9U5j6UOhqu0HCDS0jhpYfa2Wgk",
  "authDomain": "crackme-1b52a.firebaseapp.com",
  "databaseURL": "https://crackme-1b52a-default-rtdb.firebaseio.com",
  "storageBucket": "crackme-1b52a.appspot.com"
}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()

user = auth.sign_in_with_email_and_password("admin@sekai.team", "s3cr3t_SEKAI_P@ss")
uid = user.get("localId")

db = firebase.database()

path = db.child("users").child(uid).child("flag")
print(path.get(user['idToken']).val())
```

Which gives us:

    SEKAI{15_React_N@71v3_R3v3rs3_H@RD???}


# X64 Extension

    I think implementing Crypto in assembly will make stuff run faster so why not do so?

In X64 Extension we are a given a statically linked linux binary that using AES-NI encrypts a "flag.txt" to a "flag.txt.enc".
We are given an encrypted file and are suppost to decrypt it.

## Solution

Searching for the file names of "flag.txt" / "flag.txt.enc" reveals the `main` function of the binary at address `0x4048f7`.
From there it is possible to make out that the program is opening "flag.txt", reading it, doing something with it and a buffer of size 0xa0 and writing that buffer to "flag.txt.enc".
Starting at address `0x404519` we have our AES Encrypt:

![](img/aesenc.png)

Notable is that before the AES Encryption a XOR with a buffer happens which contains the previous encrypted block (or the IV in the first iteration), so the program operates in Cipher Block Chaining mode.

Placing a breakpoint before that `pxor` at `0x404616` and reading it gives us the IV of `fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0`

```
> p/x $xmm1
$1 = {
  v8_bfloat16 = {0xfeff, 0xfcfd, 0xfafb, 0xf8f9, 0xf6f7, 0xf4f5, 0xf2f3, 0xf0f1},
  v8_half = {0xfeff, 0xfcfd, 0xfafb, 0xf8f9, 0xf6f7, 0xf4f5, 0xf2f3, 0xf0f1},
  v4_float = {0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3},
  v2_double = {0xf8f9fafbfcfdfeff, 0xf0f1f2f3f4f5f6f7},
  v16_int8 = {0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0},
  v8_int16 = {0xfeff, 0xfcfd, 0xfafb, 0xf8f9, 0xf6f7, 0xf4f5, 0xf2f3, 0xf0f1},
  v4_int32 = {0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3},
  v2_int64 = {0xf8f9fafbfcfdfeff, 0xf0f1f2f3f4f5f6f7},
  uint128 = 0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
}
```

Similarly we can extract the key at the start of the key expansion at `0x4046f7` and get `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`.

The code implementation of the actual AES-256 follows very close to the [official intel guide](https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf).
Notable is that different round constants were used for the `aeskeygenassist` instructions so standard AES-256 will not work the same.

```python
pyaes.AES.rcon = [ 0x13, 0x33, 0x37, 0xba, 0xda, 0x55, 0x66] 
aes = pyaes.AESModeOfOperationCBC(KEY, iv=IV)
decrypted = b''
for i in range(len(CIPHERTEXT)//16):
    decrypted += aes.decrypt(CIPHERTEXT[16*i:16*(i+1)])
print(decrypted)
```

Gives us:

    Hey Sekai CTF Player, I hope you are fine and are enjoying the CTF.
    Keep going, here is your reward!
    The flag is SEKAI{Pl34Se_It'5_jUs7_@_wAaaarmUp}


# Secure Computing

    I heard that Windows allows any process to interact with any other process. Good thing all the important parts of my program execute directly in the kernel!
    
Secure Computing is a Windows 10/11 challenge that uses syscalls to verify a flag. Because syscalls are extremely version specific the challenge provides adjusted challenge binaries for various Windows 10 and 11 builds.

## Solution

For the binary to work for me I used the build 22621 version.

Running the binary gives us a prompt that asks for a password:

```
Welcome to my secure crackme, now powered by secure ring-0 encryption services (patent pending).
This executable requires kernel versions 22621 or 22631 (Windows 11 22H2 or 23H2) to work correctly. Check your OS version with `winver` and download a different version from the SekaiCTF website if necessary.

Enter the secret code:
FLAG_HERE

Verifying...
That's incorrect! Sorry :(
```


An initial look shows that pretty much the entire 50 MB binary is just syscalls without any obvious control flow or other operations.

![](img/sc-ep.png)

My first step was using hfiref0x's [Windows Syscall Tables](https://github.com/j00ru/windows-syscalls).
For my setup specifically this meant [NT10/ntos/22621.txt](https://github.com/hfiref0x/SyscallTables/blob/master/Compiled/Composition/X86_64/NT10/ntos/22621.txt).

The `securecomputing_syscall_trace.py` script gives a very broad overview of the program (and a valuable reference during the entire reversing process):

```
0x401046 NtWriteFile {'FileHandle': 'qword ptr [rbx + 0x28]', 'Event': '0', 'ApcRoutine': '0', 'ApcContext': '0', 'IoStatusBlock': '0xa00168', 'Buffer': '0xa00018', 'Length': '0x14b'}
0x401093 NtReadFile {'FileHandle': 'qword ptr [r12 + 0x20]', 'Event': '0', 'ApcRoutine': '0', 'ApcContext': '0', 'IoStatusBlock': '0xa00178', 'Buffer': '0xa00000', 'Length': '0x18'}
0x4010de NtWriteFile {'FileHandle': 'qword ptr [rbx + 0x28]', 'Event': '0', 'ApcRoutine': '0', 'ApcContext': '0', 'IoStatusBlock': '0xa00198', 'Buffer': '0xa00188', 'Length': '0xe'}
0x401115 NtCreateIoCompletion {'IoCompletionHandle': '0xa001a8', 'DesiredAccess': '0x1f0003', 'ObjectAttributes': '0', 'NumberOfConcurrentThreads': '0'}
0x401157 NtCreateWorkerFactory {'WorkerFactoryHandleReturn': '0xa001a8', 'DesiredAccess': '0xf00ff', 'ObjectAttributes': '0', 'CompletionPortHandle': 'qword ptr [0xa001a8]', 'WorkerProcessHandle': '0xffffffffffffffff', 'StartRoutine': '0x0', 'MaxThreadCount': '0xffffffffffffffff', 'StackReserve': '0x1000', 'StackCommit': '0x1000'}
0x4011a0 NtReadVirtualMemory {'ProcessHandle': '0xffffffffffffffff', 'BaseAddress': '0xa00231', 'Buffer': '0xa150dc', 'NumberOfBytesToRead': '4'}
0x4011de NtWriteVirtualMemory {'ProcessHandle': '0xffffffffffffffff', 'BaseAddress': '0xa150d8', 'Buffer': '0xa00235', 'NumberOfBytesToWrite': '4'}
Goto Rip 0x401200
0x4011fe NtContinue {'ThreadContext': '0xa15040', 'RaiseAlert': '0'}
0x40123f NtReadVirtualMemory {'ProcessHandle': '0xffffffffffffffff', 'BaseAddress': '0xa00242', 'Buffer': '0xa1561c', 'NumberOfBytesToRead': '4'}
0x40127d NtWriteVirtualMemory {'ProcessHandle': '0xffffffffffffffff', 'BaseAddress': '0xa15618', 'Buffer': '0xa00246', 'NumberOfBytesToWrite': '4'}
Goto Rip 0x40129f
0x40129d NtContinue {'ThreadContext': '0xa15580', 'RaiseAlert': '0'}
0x4012d7 NtWriteVirtualMemory {'ProcessHandle': '0xffffffffffffffff', 'BaseAddress': '0xa15b58', 'Buffer': 'r14', 'NumberOfBytesToWrite': '1'}
0x40130e NtReadVirtualMemory {'ProcessHandle': '0xffffffffffffffff', 'BaseAddress': 'rdi', 'Buffer': '0xa15b59', 'NumberOfBytesToRead': '1'}
Goto Rip 0x401330
0x40132e NtContinue {'ThreadContext': '0xa15ac0', 'RaiseAlert': '0'}
0x40136f NtWriteVirtualMemory {'ProcessHandle': '0xffffffffffffffff', 'BaseAddress': '0xa1609c', 'Buffer': '0xa00253', 'NumberOfBytesToWrite': '4'}
0x4013ad NtWriteVirtualMemory {'ProcessHandle': '0xffffffffffffffff', 'BaseAddress': '0xa16098', 'Buffer': '0xa00257', 'NumberOfBytesToWrite': '4'}
```

After this comes a long process of understanding the program behavior that can be summarized as the following:

`NtWriteFile` is used to write output to the console.

`NtReadFile` is only used once to read our input to address `0xA00000`.

`NtTerminateProcess` is used at the end of the program to terminate it.

`NtReadVirtualMemory` and `NtWriteVirtualMemory` are used to read individual characters from the input. (Specifically they write an address belonging to the input to a buffer and then read from the address they wrote to that buffer).

`NtContinue` is mostly just used to change the next instruction pointer address and acts as a goto. (With the exception during the `NtReadVirtualMemory`/`NtWriteVirtualMemory` routines where it also changes the `rsp` register meaningfully to read values back).

`NtContinueEx` is used as a conditional goto with it only jumping if `[rdx+0x10] == 0` during the call. The program write compare values to `[rdx+0x10]` before the syscall.

`NtCreateIoCompletion` is used to make WorkerFactories.

`NtCreateWorkerFactory` creates objects with which the program interacts with using `NtSetInformationWorkerFactory` / `NtQueryInformationWorkerFactory`. Most notably the BindingCount is initialized with 0.

`NtSetInformationWorkerFactory` is used exclusively to write to the WorkerFactoryBindingCount which apparently can only ever add to the BindingCount value. So this acts as addition to a Factory.

`NtQueryInformationWorkerFactory` is used exclusively to read the WorkerFactoryBasicInformation of which the program only processes the BindingCount. This acts as reading the value from a Factory.

`NtCreateSemaphore` is another funny thing the program uses. Specifically it is used for comparison by setting the `InitialCount` to a value that will be compared to the `MaximumCount` parameter. If `InitialCount` > `MaximumCount` a non-zero error will be returned (zero otherwise) which is then used to conditionally jump.


This overall describes the entire magic of Secure Computing.
We have primitives for jump, jump if not zero, set zero, addition and comparison for computing and the program uses that to decide if an input is correct or not.

Now the fun part of this challenge sadly ends because the actual comparison logic is massive (if the 300k lines syscall trace wasn't telling already).

Through more analysis we get that the program reads 24 characters and has 6 checks. The word size it uses is 16 bit for all operations.
Each check starts with a chain of `NtReadVirtualMemory`/`NtWriteVirtualMemory` which reads the 4 characters used in the block.
Using them as a delimiter we can separate the whole comparison into 6 individual checks, which when (naively) lifted are still ~20000 lines of C code each.

See the `securecomputing_dumpcheck.py` script for many hours of painful debugging (warning: ctf-quality code).


The starting address for the checks are respectively: `0x4014FF`, `0x725A0C`, `0x70FAE5`, `0x88E271`, `0x443F66`, `0x5C726E`

For the input character / shuffling used (left higher bits, right lower bits):

- Block 0: input[9] input[5] and input[F] input[6]
- Block 1: input[0x7] input[0xC] and input[0xA] input[3]
- Block 2: input[0xB] input[0x16] and input[0x10] input[4] 
- Block 3: input[0x8] input[0x14] and input[0x15] input[0x17]
- Block 4: input[0x11] input[2] and input[1]    input[0xD] 
- Block 5: input[0] input[0xE] and input[0x13] input[0x12]


Running `securecomputing_dumpcheck.py` for the respective start address gives C output that represents the checks.
Slight manual fixing is needed to make this useful:

- Search for `//` and consider the basic block with it as successful (`return 1`)
- Search for `dword ptr [0xa00228]` and consider basic blocks with it as unsuccessful (` return 0`)
- Search for ` <= 0x0` and replace the `0x0` with the variable used in the comparison above, these are equality checks


The basic blocks that reach the `// ADDRESS [...]` lead to the next check, which means we passed the current check.
The basic blocks that add `dword ptr [0xa00228]` to `rbx` increase the "failed check" counter, so we failed the current check.

For example for `Block 0` it should initially look like this:

```C
if(rbp <= 0x4b13) {
    LABEL_0x5f45ac:
    if(0x4b13 <= 0x0) {
        LABEL_0x7c1e52:
        if(r14 <= 0xcf76) {
            LABEL_0x4831da:
            if(0xcf76 <= 0x0) {
                LABEL_0x725671:
                // 0x7256ad ['NtWriteVirtualMemory', 'NtWriteVirtualMemory', 'NtContinue']
            } else {
                LABEL_0x6cc56e:
                addTo(rbx, dword ptr [0xa00228]);
                goto LABEL_0x725671;
            }
        } else {
            goto LABEL_0x6cc56e;
        }
    } else {
        LABEL_0x6fdd8a:
        addTo(rbx, dword ptr [0xa00228]);
        goto LABEL_0x7c1e52;
    }
} else {
    goto LABEL_0x6fdd8a;
}
```

and after fixing it look like this:

```C
if(rbp <= 0x4b13) {
    LABEL_0x5f45ac:
    if(0x4b13 <= rbp) {
        LABEL_0x7c1e52:
        if(r14 <= 0xcf76) {
            LABEL_0x4831da:
            if(0xcf76 <= r14) {
                LABEL_0x725671:
                return 1;
            } else {
                LABEL_0x6cc56e:
                return 0;
            }
        } else {
            goto LABEL_0x6cc56e;
        }
    } else {
        LABEL_0x6fdd8a:
        return 0;
    }
} else {
    goto LABEL_0x6fdd8a;
}
```


Now using a small wrapper with some macros we can bruteforce each of the 6 checks individually:

```C
#include <stdio.h>
#include <omp.h>

// gcc secureCodeWrapper.c -O3 -o secureCodeWrapper -fopenmp

#define readFrom(x) (x&0xffff)
#define addTo(x, y) x += y
#define createZeroFactory() 0

unsigned short process(unsigned short x, unsigned short y) {
    
    unsigned short rsi;
    unsigned short rdi;
    unsigned short r11;
    unsigned short r12;
    unsigned short r13;
    unsigned short r14;
    unsigned short r15;
    unsigned short rbp;
    
    // Block 0
    rsi = x;
    r14 = y;
    #include "secureCodeBlock0.c"
    
    // Other initial variable assignments for other blocks (see secureCodeWrapper.c)
    
}

void main() {
    #pragma omp parallel for
    for(int i=0;i<0x7FFF;i++) {
        if(i%0x100 == 0) {printf("@ %04X\n", i);}
        for(int j=0;j<0x7FFF;j++) {
            if(process(i, j) != 0) {
                printf("process %04X ? %04X => %04X\n", i, j, process(i, j));
            }
        }
    }
}
```

This gives us for the 6 checks:

- Block 0: process 336C ? 336C => 0001
- Block 1: process 5F34 ? 5F63 => 0001
- Block 2: process 6D33 ? 5F34 => 0001
- Block 3: process 6D34 ? 3234 => 0001
- Block 4: process 3235 ? 7979 => 0001
- Block 5: process 7362 ? 3963 => 0001

```python
s = ['X']*0x18
s[9] = chr(0x33)
s[5] = chr(0x6C)
s[0xF] = chr(0x33)
s[6] = chr(0x6C)
s[0x7] = chr(0x5F)
s[0xC] = chr(0x34)
s[0xA] = chr(0x5F)
s[3] = chr(0x63)
s[0xB] = chr(0x6D)
s[0x16] = chr(0x33)
s[0x10] = chr(0x5F)
s[4] = chr(0x34)
s[0x8] = chr(0x6D)
s[0x14] = chr(0x34)
s[0x15] = chr(0x32)
s[0x17] = chr(0x34)
s[0x11] = chr(0x32)
s[0x2] = chr(0x35)
s[0x1] = chr(0x79)
s[0xD] = chr(0x79)
s[0] = chr(0x73)
s[0xE] = chr(0x62)
s[0x13] = chr(0x39)
s[0x12] = chr(0x63)
print(''.join(s))

# sy5c4ll_m3_m4yb3_2c94234
```

Which is the correct input

```
Welcome to my secure crackme, now powered by secure ring-0 encryption services (patent pending).
This executable requires kernel versions 22621 or 22631 (Windows 11 22H2 or 23H2) to work correctly. Check your OS version with `winver` and download a different version from the SekaiCTF website if necessary.

Enter the secret code:
sy5c4ll_m3_m4yb3_2c94234

Verifying...
Congratulations! Submit as SEKAI{<your input here>} to receive your reward!
```