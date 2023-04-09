# unreal

    Description
    Unreal or BeReal?
    
The challenge is a 2kb RAR archive that when extracted throws an "CRC failed" error, ignoring that extracts the string "OK"

## Solution

Based on the format this likely a RARVM Challenge.
I authored a tool for interacting with the rarvm (and a small paper explaining the VM) a few years ago, so just using my [Tool](https://github.com/Pusty/rarvm-debugger) we can just extract the used code.

The program contains a bit more not used code, tracing it reveals all the necessary information though:

```
$ ./rarvm-debugger d -trace unreal.rar
  [0000] JMP      #0x000000A3
  [00A3] MOVD     R3, #0x00001000
  [00A4] MOVD     R0, #0x0000003A
  [00A5] XOR      R0, #0x00000057
  [00A6] MOVD     [R3+#0x00000000], R0
  [00A7] MOVD     R0, #0x0000001F
  [00A8] XOR      R0, #0x00000076
  [00A9] MOVD     [R3+#0x00000000], R0
  [00AA] MOVD     R0, #0x000000B8
  [00AB] XOR      R0, #0x000000DC
  [00AC] MOVD     [R3+#0x00000000], R0
  [00AD] MOVD     R0, #0x00000029
  [00AE] XOR      R0, #0x00000047
  [00AF] MOVD     [R3+#0x00000000], R0
  [00B0] MOVD     R0, #0x00000086
  [00B1] XOR      R0, #0x000000EF
  [00B2] MOVD     [R3+#0x00000000], R0
  [00B3] MOVD     R0, #0x00000071
  [00B4] XOR      R0, #0x00000016
  [00B5] MOVD     [R3+#0x00000000], R0
  [00B6] MOVD     R0, #0x0000004E
  [00B7] XOR      R0, #0x00000026
  [00B8] MOVD     [R3+#0x00000000], R0
  [00B9] MOVD     R0, #0x000000F0
  [00BA] XOR      R0, #0x00000084
  [00BB] MOVD     [R3+#0x00000000], R0
  [00BC] MOVD     R0, #0x00000092
  [00BD] XOR      R0, #0x000000E9
  [00BE] MOVD     [R3+#0x00000000], R0
  [00BF] MOVD     R0, #0x000000C5
  [00C0] XOR      R0, #0x000000B7
  [00C1] MOVD     [R3+#0x00000000], R0
  [00C2] MOVD     R0, #0x0000009A
  [00C3] XOR      R0, #0x000000FB
  [00C4] MOVD     [R3+#0x00000000], R0
  [00C5] MOVD     R0, #0x000000D7
  [00C6] XOR      R0, #0x000000A5
  [00C7] MOVD     [R3+#0x00000000], R0
  [00C8] MOVD     R0, #0x000000E4
  [00C9] XOR      R0, #0x000000B2
  [00CA] MOVD     [R3+#0x00000000], R0
  [00CB] MOVD     R0, #0x00000065
  [00CC] XOR      R0, #0x00000028
  [00CD] MOVD     [R3+#0x00000000], R0
  [00CE] MOVD     R0, #0x00000037
  [00CF] XOR      R0, #0x00000068
  [00D0] MOVD     [R3+#0x00000000], R0
  [00D1] MOVD     R0, #0x000000F2
  [00D2] XOR      R0, #0x0000009B
  [00D3] MOVD     [R3+#0x00000000], R0
  [00D4] MOVD     R0, #0x00000011
  [00D5] XOR      R0, #0x00000062
  [00D6] MOVD     [R3+#0x00000000], R0
  [00D7] MOVD     R0, #0x0000008A
  [00D8] XOR      R0, #0x000000D5
  [00D9] MOVD     [R3+#0x00000000], R0
  [00DA] MOVD     R0, #0x0000005D
  [00DB] XOR      R0, #0x0000002E
  [00DC] MOVD     [R3+#0x00000000], R0
  [00DD] MOVD     R0, #0x0000006E
  [00DE] XOR      R0, #0x0000001A
  [00DF] MOVD     [R3+#0x00000000], R0
  [00E0] MOVD     R0, #0x000000B1
  [00E1] XOR      R0, #0x000000D8
  [00E2] MOVD     [R3+#0x00000000], R0
  [00E3] MOVD     R0, #0x000000C8
  [00E4] XOR      R0, #0x000000A4
  [00E5] MOVD     [R3+#0x00000000], R0
  [00E6] MOVD     R0, #0x00000043
  [00E7] XOR      R0, #0x0000002F
  [00E8] MOVD     [R3+#0x00000000], R0
  [00E9] MOVD     R0, #0x000000A9
  [00EA] XOR      R0, #0x000000F6
  [00EB] MOVD     [R3+#0x00000000], R0
  [00EC] MOVD     R0, #0x00000025
  [00ED] XOR      R0, #0x0000004A
  [00EE] MOVD     [R3+#0x00000000], R0
  [00EF] MOVD     R0, #0x0000004B
  [00F0] XOR      R0, #0x0000003E
  [00F1] MOVD     [R3+#0x00000000], R0
  [00F2] MOVD     R0, #0x0000000F
  [00F3] XOR      R0, #0x0000007B
  [00F4] MOVD     [R3+#0x00000000], R0
  [00F5] MOVD     R0, #0x00000072
  [00F6] XOR      R0, #0x0000002D
  [00F7] MOVD     [R3+#0x00000000], R0
  [00F8] MOVD     R0, #0x00000066
  [00F9] XOR      R0, #0x00000012
  [00FA] MOVD     [R3+#0x00000000], R0
  [00FB] MOVD     R0, #0x0000009C
  [00FC] XOR      R0, #0x000000F4
  [00FD] MOVD     [R3+#0x00000000], R0
  [00FE] MOVD     R0, #0x00000083
  [00FF] XOR      R0, #0x000000E6
  [0100] MOVD     [R3+#0x00000000], R0
  [0101] MOVD     R0, #0x00000021
  [0102] XOR      R0, #0x00000053
  [0103] MOVD     [R3+#0x00000000], R0
  [0104] MOVD     R0, #0x000000BD
  [0105] XOR      R0, #0x000000D8
  [0106] MOVD     [R3+#0x00000000], R0
  [0107] MOVD     R0, #0x000000EF
  [0108] XOR      R0, #0x00000092
  [0109] MOVD     [R3+#0x00000000], R0
  [010A] JMP      #0x00000111
  [0111] MOVD     [#0x00001000], #0x000A4B4F
  [0112] MOVD     [#0x0003C020], #0x00001000
  [0113] MOVD     [#0x0003C01C], #0x00000003
  [0114] CALL     #0x0000000B
  [000B] OR       R0, R1
  [000C] MOVD     R1, [R6+#0x00000008]
  [000D] SHL      R1, #0x00000008
  [000E] AND      R1, #0x00FF0000
  [000F] OR       R0, R1
  [0010] MOVD     R1, [R6+#0x00000008]
  [0011] SHL      R1, #0x00000018
  [0012] AND      R1, #0xFF000000
  [0013] OR       R0, R1
  [0014] MOVD     R7, R6
  [0015] POP      R6
  [0016] RET
OK
```


Simply looking at it

```
  [00A4] MOVD     R0, #0x0000003A
  [00A5] XOR      R0, #0x00000057
  [00A6] MOVD     [R3+#0x00000000], R0
  [00A7] MOVD     R0, #0x0000001F
  [00A8] XOR      R0, #0x00000076
  [00A9] MOVD     [R3+#0x00000000], R0
```

We can see it moves a value to register 0, xors it with a constant, and writes it the address pointed to by register 3, this is done a couple of times.

Using a small script to xor these constants and concatinate the resulting character yields the flag:

```python
bc = """MOVD     R0, #0x0000003A
XOR      R0, #0x00000057
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x0000001F
XOR      R0, #0x00000076
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x000000B8
XOR      R0, #0x000000DC
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000029
XOR      R0, #0x00000047
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000086
XOR      R0, #0x000000EF
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000071
XOR      R0, #0x00000016
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x0000004E
XOR      R0, #0x00000026
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x000000F0
XOR      R0, #0x00000084
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000092
XOR      R0, #0x000000E9
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x000000C5
XOR      R0, #0x000000B7
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x0000009A
XOR      R0, #0x000000FB
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x000000D7
XOR      R0, #0x000000A5
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x000000E4
XOR      R0, #0x000000B2
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000065
XOR      R0, #0x00000028
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000037
XOR      R0, #0x00000068
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x000000F2
XOR      R0, #0x0000009B
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000011
XOR      R0, #0x00000062
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x0000008A
XOR      R0, #0x000000D5
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x0000005D
XOR      R0, #0x0000002E
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x0000006E
XOR      R0, #0x0000001A
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x000000B1
XOR      R0, #0x000000D8
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x000000C8
XOR      R0, #0x000000A4
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000043
XOR      R0, #0x0000002F
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x000000A9
XOR      R0, #0x000000F6
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000025
XOR      R0, #0x0000004A
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x0000004B
XOR      R0, #0x0000003E
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x0000000F
XOR      R0, #0x0000007B
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000072
XOR      R0, #0x0000002D
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000066
XOR      R0, #0x00000012
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x0000009C
XOR      R0, #0x000000F4
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000083
XOR      R0, #0x000000E6
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x00000021
XOR      R0, #0x00000053
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x000000BD
XOR      R0, #0x000000D8
MOVD     [R3+#0x00000000], R0
MOVD     R0, #0x000000EF
XOR      R0, #0x00000092
MOVD     [R3+#0x00000000], R0"""

bc = bc.split("\n")

index = 0
out = ''
for line in bc:
    if index % 3 == 0:
        first = int(line.split("R0, #")[1], 16)
    if index % 3 == 1:
        snd = int(line.split("R0, #")[1], 16)
    if index % 3 == 2:
        out += (chr(first^snd))
    index += 1
    
print(out)
```

`midnight{rarVM_is_still_out_there}`