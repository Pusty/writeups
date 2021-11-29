# NFT

    Description:
    Same as Easy NFT, but harder.

NFT is a network traffic capture file containing nftables (NFT) setup traffic. The goal is to figure out what to send the provided server so it returns the flag.


## Solution

For the `easy-nft` challenge my teammate Aaron wrote [a script](parse.py) to convert the pcap files into a [way more expressive format](dump.txt) which looks like this:

```
[...]
{'attrs': [('NFTA_RULE_TABLE', 'filter'),
           ('NFTA_RULE_CHAIN', 'output'),
           ('NFTA_RULE_HANDLE', 5),
           ('NFTA_RULE_EXPRESSIONS', [{'attrs': [('NFTA_EXPR_NAME', 'immediate'), ('NFTA_EXPR_DATA', {'attrs': [('NFTA_IMMEDIATE_DREG', 'NFT_REG_VERDICT'), ('NFTA_IMMEDIATE_DATA', {'attrs': [('NFTA_DATA_VERDICT', {'attrs': [('NFTA_VERDICT_CODE', 'NFT_JUMP'), ('NFTA_VERDICT_CHAIN', 'hack')]})]})]})]}])],
 'header': {'flags': 2050,
            'length': 120,
            'pid': 8974,
            'sequence_number': 0,
            'type': 2566},
 'nfgen_family': 2,
 'res_id': 55809,
 'version': 0}
[...]
```

Based on this it was possible for us to reconstruct what is happening:


```python
def output():
    hack()
    
def hack():
    NFT_REG_1 = NFT_PAYLOAD_TRANSPORT_HEADER[28:28+8]
    if NFT_REG_1 != b'\x88\xd8\x88K\xe0V\xcf\xf3': # if the header isn't correct do nothing
        return
    
    # encode the 44:76 header
    NFT_REG32_01 = b'\x00\x00\x00\x00'
    NFT_REG32_01 = NFT_PAYLOAD_TRANSPORT_HEADER[44]
    f()
    NFT_REG_3 = b[NFT_REG32_03]
    g()
    NFT_REG32_01 = b[NFT_REG_4]
    NFT_PAYLOAD_TRANSPORT_HEADER[44] = NFT_REG32_01
    
    ... repeated for 45 to 74
    
    NFT_REG32_01 = b'\x00\x00\x00\x00'
    NFT_REG32_01 = NFT_PAYLOAD_TRANSPORT_HEADER[75]
    f()
    NFT_REG_3 = b[NFT_REG32_03]
    g()
    NFT_REG32_01 = b[NFT_REG_4]
    NFT_PAYLOAD_TRANSPORT_HEADER[75] = NFT_REG32_01
    
    NFT_REG_1 = NFT_PAYLOAD_TRANSPORT_HEADER[44:60]
    NFT_REG_2 = NFT_PAYLOAD_TRANSPORT_HEADER[60:76]
    NFT_REG_3 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    NFT_PAYLOAD_TRANSPORT_HEADER[44:60] = NFT_REG_3 # zero the encoded header
    NFT_PAYLOAD_TRANSPORT_HEADER[60:76] = NFT_REG_3
    
    # check if the encoded header matches some fixes values
    if NFT_REG_1 == b'2I\x1dU\xad\xe6\xc6\xb3wG\xf5~\xd4X\xc9\x05':
        if NFT_REG_2 == b'r\x8f\x9aGD\xcav\xdb6\xf9\x90x6\x10\x80\xd5':
            NFT_REG32_10 = b'\x00'
            NFT_REG_1 = flag[NFT_REG32_10] # if the values match write the flag into the response packet
            NFT_PAYLOAD_TRANSPORT_HEADER[60:99] = NFT_REG_1
```

The lookup from `b` has 256 entries in the style of `{'attrs': [('NFTA_SET_ELEM_KEY', {'attrs': [('NFTA_DATA_VALUE', b'\x0f')]}), ('NFTA_SET_ELEM_DATA', {'attrs': [('NFTA_DATA_VALUE', b'v')]})]}`. It maps each byte to another byte.

Each character within the packet between byte 44 and 76 gets encoded and then checked if they match a hardcoded value.
`hack` itself is missing the code of `f` and `g` so let's look at them as well:

```python

a = {   0x00 ^ 0x5e: func_0, 
        0x01 ^ 0x5e: func_1,
        0x02 ^ 0x5e: func_2,
        0x03 ^ 0x5e: func_3,
        0x04 ^ 0x5e: func_4,
        0x05 ^ 0x5e: func_5,
        0x06 ^ 0x5e: func_6,
        0x07 ^ 0x5e: func_7,
        0x08 ^ 0x5e: func_8,
        0x09 ^ 0x5e: func_9,
        0x0A ^ 0x5e: func_10,
        0x0B ^ 0x5e: func_11,
        0x0C ^ 0x5e: func_12,
        0x0D ^ 0x5e: func_13,
        0x0E ^ 0x5e: func_14,
        0x0F ^ 0x5e: func_15,
        (0x00 + 0x10) ^ 0xb7: func_16, 
        (0x01 + 0x10) ^ 0xb7: func_17, 
        (0x02 + 0x10) ^ 0xb7: func_18, 
        (0x03 + 0x10) ^ 0xb7: func_19, 
        (0x04 + 0x10) ^ 0xb7: func_20, 
        (0x05 + 0x10) ^ 0xb7: func_21, 
        (0x06 + 0x10) ^ 0xb7: func_22, 
        (0x07 + 0x10) ^ 0xb7: func_23, 
        (0x08 + 0x10) ^ 0xb7: func_24, 
        (0x09 + 0x10) ^ 0xb7: func_25, 
        (0x0A + 0x10) ^ 0xb7: func_26, 
        (0x0B + 0x10) ^ 0xb7: func_27, 
        (0x0C + 0x10) ^ 0xb7: func_28, 
        (0x0D + 0x10) ^ 0xb7: func_29, 
        (0x0E + 0x10) ^ 0xb7: func_30, 
        (0x0F + 0x10) ^ 0xb7: func_31
    }

def f():
    NFT_REG32_15 = numgen()%16 + 0
    NFT_REG32_15 = NFT_REG32_15 ^ 0x5e
    a[NFT_REG32_15]()
    
def g():
    NFT_REG32_15 = numgen()%16 + 16
    NFT_REG32_15 = NFT_REG32_15 ^ 0xb7
    a[NFT_REG32_15]()
    
def func_0():
    NFT_REG32_03 = NFT_REG32_01 ^ 0xad
    
... same for 1..15 just different xor key

def func_16():
    NFT_REG_4 = NFT_REG_3 ^ 0xca

... same for 17..31 just different xor key
    
```

with this the encoding of the input can be summarized as:

```python

tableF = xorKeys from func_0 to func_15
tableG = xorKeys from func_16 to func_31
tableB = the large 'b' table


for i in range(44, 76):
    NFT_REG32_01 = b'\x00\x00\x00\x00'
    NFT_REG32_01 = NFT_PAYLOAD_TRANSPORT_HEADER[i]
    NFT_REG32_03 = NFT_REG32_01 ^ tableF[(i-44)%16]
    NFT_REG_3    = b[NFT_REG32_03]
    NFT_REG_4    = NFT_REG_3 ^ tableG[(i-44)%16]
    NFT_REG32_01 = b[NFT_REG_4]
    NFT_PAYLOAD_TRANSPORT_HEADER[i] = NFT_REG32_01
    
# CORRECTNFT_PAYLOAD_TRANSPORT_HEADER[44:76] = b'2I\x1dU\xad\xe6\xc6\xb3wG\xf5~\xd4X\xc9\x05r\x8f\x9aGD\xcav\xdb6\xf9\x90x6\x10\x80\xd5'
    
```

As the encoded and verification of each character isn't dependent on any other, each character can quickly bruteforced individually.

A [quick solver script](solve.py) tells that the correct input is `a8a7024176baa3f10b9d67abd1e5df25b4773416ee4de1e21d6268941a962bcf`


`sudo hping3 nft.hackable.software -d 128 -j -1 -E ./payload -c 1` returns the flag `DrgnS{caf6f49e668ab2107f01100230321550}`.