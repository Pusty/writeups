# FlagSecurityEngine

    The Kalmar FlagSecurityEngine™'s usage of the loadall() function will surely protect the flag from reverse engineering, right?

The challenge provides source code for wrapper around quickjs. The task is to reverse engineer code that has been compiled to quickjs bytecode.

## Solution

The first part is getting the bytecode in a readable format.
For this modifying the quickjs source code works good.
As in the `makedep.sh` we get the repository and the apply the following patch to get a dump of functions executed at runtime (since the normal DUMP_BYTECODE is not enough to get the functions made from bytecode).

```patch
diff --git a/quickjs.c b/quickjs.c
index 642ae34..a634d0e 100644
--- a/quickjs.c
+++ b/quickjs.c
@@ -90,7 +90,7 @@
   32: dump line number table
   64: dump compute_stack_size
  */
-//#define DUMP_BYTECODE  (1)
+#define DUMP_BYTECODE  (1)
 /* dump the occurence of the automatic GC */
 //#define DUMP_GC
 /* dump objects freed by the garbage collector */
@@ -16154,6 +16154,8 @@ typedef enum {
 #define FUNC_RET_YIELD_STAR    2
 #define FUNC_RET_INITIAL_YIELD 3
 
+static __maybe_unused void js_dump_function_bytecode(JSContext *ctx, JSFunctionBytecode *b);
+
 /* argv[] is modified if (flags & JS_CALL_FLAG_COPY_ARGV) = 0. */
 static JSValue JS_CallInternal(JSContext *caller_ctx, JSValueConst func_obj,
                                JSValueConst this_obj, JSValueConst new_target,
@@ -16276,6 +16278,7 @@ static JSValue JS_CallInternal(JSContext *caller_ctx, JSValueConst func_obj,
     ctx = b->realm; /* set the current realm */
 
  restart:
+    js_dump_function_bytecode(ctx, b);
     for(;;) {
         int call_argc;
         JSValue *call_argv;
@@ -29882,7 +29885,7 @@ static void dump_byte_code(JSContext *ctx, int pass,
         has_loc:
             printf(" %d: ", idx);
             if (idx < var_count) {
-                print_atom(ctx, vars[idx].var_name);
+                //print_atom(ctx, vars[idx].var_name);
             }
             break;
         case OP_FMT_none_arg:
@@ -29893,7 +29896,7 @@ static void dump_byte_code(JSContext *ctx, int pass,
         has_arg:
             printf(" %d: ", idx);
             if (idx < arg_count) {
-                print_atom(ctx, args[idx].var_name);
+                //print_atom(ctx, args[idx].var_name);
             }
             break;
         case OP_FMT_none_var_ref:
@@ -29904,7 +29907,7 @@ static void dump_byte_code(JSContext *ctx, int pass,
         has_var_ref:
             printf(" %d: ", idx);
             if (idx < closure_var_count) {
-                print_atom(ctx, closure_var[idx].var_name);
+                //print_atom(ctx, closure_var[idx].var_name);
             }
             break;
         default:

```

Running the compiled binary against the `chall.js` provides the following functions:

```
function: checkFlag
  mode:
  stack_size: 32
  opcodes:
        set_loc_uninitialized 4: 
        set_loc_uninitialized 3: 
        set_loc_uninitialized 2: 
        set_loc_uninitialized 1: 
        set_loc_uninitialized 0: 
        fclosure8 0: [bytecode <null>]
        set_name _
        put_loc0 0: 
        get_loc_check 0: 
        put_loc1 1: 
        push_const8 1: 3554697097
        put_loc2 2: 
        push_empty_string
        put_loc3 3: 
        push_i8 98
        push_i8 57
        push_i8 35
        push_i8 34
        push_i8 42
        push_i8 41
        push_i8 104
        push_i8 79
        push_i8 18
        push_i8 28
        push_i8 29
        push_i8 75
        push_i8 55
        push_0 0
        push_i8 49
        push_i8 33
        push_i8 37
        push_i8 46
        push_i8 65
        push_i8 21
        push_i8 120
        push_i8 99
        push_i8 123
        push_i8 68
        push_i8 112
        push_i8 20
        push_i8 78
        push_i8 19
        push_i8 61
        push_i8 31
        push_i8 54
        push_i8 122
        array_from 32
        push_i8 39
        define_field "32"
        push_i8 123
        define_field "33"
        push_i8 23
        define_field "34"
        push_i8 29
        define_field "35"
        push_i8 30
        define_field "36"
        push_i8 52
        define_field "37"
        push_7 7
        define_field "38"
        push_5 5
        define_field "39"
        push_i8 103
        define_field "40"
        push_7 7
        define_field "41"
        push_i8 95
        define_field "42"
        push_i8 127
        define_field "43"
        push_5 5
        define_field "44"
        push_i8 57
        define_field "45"
        push_i8 58
        define_field "46"
        push_6 6
        define_field "47"
        push_i8 105
        define_field "48"
        push_i8 84
        define_field "49"
        push_i8 60
        define_field "50"
        push_i8 55
        define_field "51"
        push_i8 34
        define_field "52"
        push_i8 44
        define_field "53"
        push_i8 100
        define_field "54"
        push_i8 90
        define_field "55"
        push_i8 84
        define_field "56"
        push_i8 100
        define_field "57"
        push_4 4
        define_field "58"
        push_i8 12
        define_field "59"
        push_i8 59
        define_field "60"
        push_i8 54
        define_field "61"
        push_i8 64
        define_field "62"
        push_i8 76
        define_field "63"
        push_i8 92
        define_field "64"
        push_i8 120
        define_field "65"
        get_field2 map
        fclosure8 2: [bytecode <null>]
        call_method 1
        get_field2 join
        push_empty_string
        call_method 1
        put_loc8 4: 
        set_loc_uninitialized 5: 
        push_0 0
        put_loc8 5: 
  357:  get_loc_check 5: 
        get_arg0 0: 
        get_length
        lt
        if_false8 440
        get_loc_check 3: 
        get_var String
        get_field2 fromCharCode
        get_arg0 0: 
        get_field2 charCodeAt
        get_loc_check 5: 
        call_method 1
        get_loc_check 2: 
        push_i8 95
        and
        xor
        call_method 1
        add
        dup
        put_loc_check 3: 
        drop
        get_loc_check 1: 
        get_loc_check 2: 
        get_arg0 0: 
        get_field2 charCodeAt
        get_loc_check 5: 
        call_method 1
        call2 2
        dup
        put_loc_check 2: 
        drop
        get_loc_check 5: 
        post_inc
        put_loc_check 5: 
        drop
        goto8 357
  440:  get_loc_check 3: 
        get_loc_check 4: 
        neq
        if_false8 462
        get_var print
        push_atom_value "Wrong flag!"
        call1 1
        drop
        return_undef
  462:  get_var print
        push_atom_value "Right flag!"
        call1 1
        drop
        return_undef
```

```
function: <null>
  mode:
  stack_size: 4
  opcodes:
        get_var String
        get_field2 fromCharCode
        get_arg0 0: 
        get_arg1 1: 
        xor
        tail_call_method 1
```

```
function: <null>
  mode:
  stack_size: 3
  opcodes:
        set_loc_uninitialized 0: 
        push_0 0
        put_loc0 0: 
    5:  get_loc_check 0: 
        push_i8 16
        lt
        if_false8 53
        get_arg0 0: 
        get_arg0 0: 
        push_i8 15
        sar
        xor
        set_arg0 0: 
        get_arg0 0: 
        push_i8 13
        shl
        xor
        set_arg0 0: 
        get_arg0 0: 
        push_i8 17
        sar
        xor
        put_arg0 0: 
        get_arg1 1: 
        get_arg0 0: 
        xor
        put_arg1 1: 
        get_arg0 0: 
        get_arg1 1: 
        push_i8 11
        sar
        xor
        put_arg0 0: 
        get_loc_check 0: 
        post_inc
        put_loc_check 0: 
        drop
        goto8 5
   53:  get_arg0 0: 
        get_arg1 1: 
        xor
        return
```

The `checkFlag` function first creates a buffer which it then maps through a function that xors each element with the index and turns it into a string.
These are concatenated and are used as a "correct flag" compare buffer.

The main logic consists out of a loop that xors each input character with a value computed from the last character.
The output is then compared against the compare buffer which then yields a positive or negative reply.

In python code it looks like this:

```python
v = [98, 57, 35, 34, 42, 41, 104, 79, 18, 28, 29, 75, 55, 0, 49, 33, 37, 46, 65, 21, 120, 99, 123, 68, 112, 20, 78, 19, 61, 31, 54, 122, 39, 123, 23, 29, 30, 52, 7, 5, 103, 7, 95, 127, 5, 57, 58, 6, 105, 84, 60, 55, 34, 44, 100, 90, 84, 100, 4, 12, 59, 54, 64, 76, 92, 120]
compareBuf = [v[i] ^ i for i in range(len(v))]

def sign_i32(value):
    value = value & ((1<<32)-1)
    value = (value ^ (1<<31)) - (1<<31)
    return value

def computeval(a,b):
    for i in range(16):
        a = sign_i32(a)
        a = (a >> 15)^a
        a = sign_i32(a)
        a = ((a << 13)^a)
        a = sign_i32(a)
        a = (a >> 17)^a
        a = sign_i32(a)
        b = b ^ a
        a = (b >> 11)^a
        a = sign_i32(a)
    return a ^ b
    
def encode(flag):
    xorVal = 3554697097
    out = []
    for i in range(len(flag)):
        c = ord(flag[i])
        out.append(c^(xorVal & 95))
        xorVal = computeval(xorVal, c)
    return bytes(out)
```

Notable here is that the internal integer format in quickjs for these operations are 32-bit signed integers (specifically the shifts right are arithmetic not logical).

Inverting this process is also very simple:

```python
def decode(buffer):
    xorVal = 3554697097
    inp = []
    for i in range(len(buffer)):
        for c in range(0x20, 0x7f):
            if c^(xorVal & 95) == buffer[i]:
                inp.append(c)
                xorVal = computeval(xorVal, c)
                break
                
    return bytes(inp)

print(decode(compareBuf))
```

Which gives us the flag `kalmar{NOW_ThA7-y0U_kn0W-HOW-Qu1CKj5-W0rKs-CaN_yOu_PWN_it_4$_WelL}`.


