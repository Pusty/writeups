# re01

The re01 challenge consists out of a windows binary and a output.png file. The binary processes a given data file and if it satisfies some constraints it creates a png file as output and prints the flag when the hash of the data matches a fixed value.

## Solution

At first the data is split into 15 arrays of a size of 0x1000 bytes.
Then some swapping of position happens, which is easily reversible, following the actual constraints on the data are checked which can be translated to the following:

```python
def confirm(arr):
    if arr[0] == 7 and arr[13] == 12:
        for l in range(1, 7):
            if ((arr[l] - 52)&0xFF) > 9: 
                return -2
        for l in range(7, 12):
            if ((arr[l] - 77)&0xFF) > 9:
                return -3
        if arr[12] - 34 <= 9:
            v4 = arr[1] ** 3
            v5 = (arr[2] ** 3) + v4
            v28 = int(math.floor((arr[3] ** 3) + v5))&0xFF
            if v28 != 0x62: return -4
            v6 = arr[4]**3
            v7 = (arr[5] ** 3) + v6
            v8 = (arr[6] ** 3) + v7
            v28 = int(math.floor(arr[7]**3)+v8)&0xFF
            if v28 != 0x6B: return -5
            v9 = arr[9] ** 3
            v10 = (arr[10] ** 3) + v9
            v11 = (arr[11] ** 3) + v10
            v28 = int(math.floor(arr[12]**3)+v11)&0xFF
            if v28 != 0xBF: return -6
            return 0 # correct data
    return -1
```

The array checked here consists out of the 10th elements of the first 14 0x1000 byte arrays.
After the checks are done the program hashes the data and checks it against a hard coded value, and if it matches it prints out the flag.
Then it replaces the 10th elements of the first 14 0x1000 byte arrays with hard coded values and writes the data in order into a `output.png` file.

The task is to figure out the original 14 byte sequence.
By brute forcing the possible values for each check individually the following possible sets can be determined:

possible for [0]:

    7

possible for [1,2,3]:

    54, 61, 61
    61, 54, 61
    61, 61, 54
    

possible for [4,5,6,7]:

    56, 58, 59, 80
    56, 59, 58, 80
    57, 61, 61, 78
    58, 56, 59, 80
    58, 59, 56, 80
    58, 59, 60, 84
    58, 60, 59, 84
    59, 56, 58, 80
    59, 58, 56, 80
    59, 58, 60, 84
    59, 59, 61, 84
    59, 60, 58, 84
    59, 61, 59, 84
    60, 58, 59, 84
    60, 59, 58, 84
    61, 57, 61, 78
    61, 59, 59, 84
    61, 61, 57, 78
    
possible for [8]:

    77
    78
    79
    80
    81
    82
    83
    84
    85
    86
    
possible for [9,10,11,12]:

    77, 79, 80, 35
    77, 80, 79, 35
    77, 81, 81, 34
    77, 81, 84, 41
    77, 84, 81, 41
    78, 78, 86, 39
    78, 86, 78, 39
    79, 77, 80, 35
    79, 80, 77, 35
    79, 82, 82, 36
    79, 83, 85, 38
    79, 85, 83, 38
    80, 77, 79, 35
    80, 79, 77, 35
    80, 81, 81, 37
    80, 82, 84, 39
    80, 84, 82, 39
    81, 77, 81, 34
    81, 77, 84, 41
    81, 80, 81, 37
    81, 81, 77, 34
    81, 81, 80, 37
    81, 82, 83, 35
    81, 83, 82, 35
    81, 84, 77, 41
    82, 79, 82, 36
    82, 80, 84, 39
    82, 81, 83, 35
    82, 82, 79, 36
    82, 83, 81, 35
    82, 84, 80, 39
    83, 79, 85, 38
    83, 81, 82, 35
    83, 82, 81, 35
    83, 85, 79, 38
    84, 77, 81, 41
    84, 80, 82, 39
    84, 81, 77, 41
    84, 82, 80, 39
    85, 79, 83, 38
    85, 83, 79, 38
    86, 78, 78, 39
    
possible for [13]:

    12
    
    
The hashing algorithm run on the modified data can be translated to the following:

```C
int64_t SHL(unsigned char* data, int length) {
    int64_t  hash = 0x2FD2B4;
    for(int i=0;i<length;i++) {
        hash = hash ^ data[i];
        hash = hash * 0x66EC73;
    }
    return hash;
}
```
    
Based on these sets I brute forced the combination which hashed results in the internal fixed values:

```python
arr = [ 7,54, 61, 61, 59, 56, 58, 80, 83, 79, 85, 83, 38, 12]
```

After rewriting the sequence into the `output.png` file the challenge shipped with and swapping the 0x1000 byte arrays in inverted order to how they were done originally, I ran the result through the challenge binary which resulted in the flag:

    Flag = WhiteHat{8333769562446613979}
    -> SHA1 WhiteHat{f19b26bc2ff97f823a0934066d7ac036cbe189a7}
