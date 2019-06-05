#include <stdio.h>
#include <ctype.h>

unsigned char encrypted[] = {0xF6, 0x2C, 0x72, 0x1A, 0x03, 0x99, 0x0E, 0x78, 0xBD, 0x90, 0xE9, 0x68, 0xD0, 0x69, 0x37, 0x29, 0xF8, 0x12, 0xF4, 0xE5, 0xD0, 0xFB, 0xF3, 0x7E, 0x72, 0x61, 0x79, 0x19, 0xED, 0x44, 0x12, 0x52, 0xF5, 0xF9, 0xAA, 0x14, 0x36, 0x0D, 0x1F, 0xB2, 0x52, 0x6B, 0xF2, 0x6A, 0xDA, 0x9D, 0xEC, 0x3C};
    

void printPart(unsigned long long value, int amount) {
    for (int i = amount-1; i >= 0; --i ) {
        unsigned char c = value&0xFF;
        value >>= 8;
        printf("%c", c);
    }
}

int isPrintable(unsigned long long value, int amount) {
    for (int i = amount-1; i >= 0; --i ) {
        unsigned char c = value&0xFF;
        value >>= 8;
        if(!isprint(c)) return 0;
    }
    return 1;
}
 
int trySolve(int value) {
    
    unsigned char input[8];
    // The value we want to figure out
    *((unsigned int*)&input[0]) = value;
    // "wT96" as the binary enforces
    *((unsigned int*)&input[4]) = 0x36395477;
    
    // Check if the password is even typable
    if(!isPrintable(*((unsigned long long*)&input[0]),8)) return 0;
    
    // Create an array filled with 0..255
    unsigned char buffer[0x100];
    for(int i=0;i<0x100;i++)
        buffer[i] = i;
    
    // First function in shell code
    unsigned char hashValue = 0;
    unsigned char curValue = 0;
    for(int i=0;i<0x100;i++) {
        curValue = buffer[i];
        hashValue = (input[i%8]+buffer[i]+hashValue);
        buffer[i] = buffer[hashValue];
        buffer[hashValue] = curValue;
    }
    
    // Second function in shell code
    unsigned char decrypted[8]; // (should be 0x30 but only 8 are interesting)
    unsigned char nextIndex = 0;
    unsigned char hashValue2 = 0;
    unsigned char nextEntry = 0;
    unsigned char hashEntry = 0;
    unsigned char resultValue = 0;
    
    for(int i=0;i<8;i++) { // as only the first 8 elements are needed for the value no more need to be calculated
        nextIndex = (nextIndex + 1);
        nextEntry = buffer[nextIndex];
        hashValue2 = (hashValue2 + nextEntry);
        hashEntry = buffer[hashValue2];
        buffer[nextIndex] = buffer[hashValue2];
        buffer[hashValue2] = nextEntry;
        decrypted[i] = encrypted[i] ^ buffer[(hashEntry+nextEntry)&0xFF];
    }
    
    // Reverse Verify

    unsigned long long c = 0;
    for (int i = 0; i < 8; i++ )
        c = ((unsigned  long long)decrypted[i]&0xFF) | (c << 8);

    // As the last part is only 4 bytes long the last 4 bytes of the xor compare are fixed
    if((c&0xFFFFFFFF00000000LL) != 0x115C28DA00000000LL) return 0;
    
    // Calculate the last part and check if it's printable
    unsigned int fp4  = c ^ 0x115C28DA834FEFFDLL;
    if(!isPrintable(fp4,4))
        return 0;

    // Calculate the third part and check if it's printable
    unsigned long long fp3 = 0x665F336B1A566B19LL ^ fp4;
    if(!isPrintable(fp3,8))
        return 0;

    // Calculate the second part and check if it's printable
    unsigned long long fp2 = 0x393B415F5A590044LL ^ fp3;
    if(!isPrintable(fp2,8))
        return 0;

    // Calculate the first part and check if it's printable
    unsigned long long fp1 = 0x3255557376F68LL ^ fp2;
    if(!isPrintable(fp1,8))
        return 0;
    
    // HOORAY! A value that matches all conditions and is actually writable
    
    // Print some values to compare against the binary
    printf("%016llx\n", c);
    puts("=>");
    printf("%016llx\n", fp1);   
    printf("%016llx\n", fp2);
    printf("%016llx\n", fp3);
    printf("%08x\n", fp4);
    
    // Output the passphrase in a line
    printPart(fp1,8);
    printPart(fp2,8);
    printPart(fp3,8);
    printPart(fp4,4);
    puts("");
    
    // Output the 4th stages matching passphrase in a line
    printPart(*((unsigned long long*)&input[0]),8);
    puts("");
    
    return 1;
}

void main() {
    puts("Starting..");
    int lastDiv = 0;
    // for 4 elements 4 loops are a quick solution and provide the ability to adjust the loop borders easier
    for(unsigned int a=0;a<0x80;a++)
        for(unsigned int b=0;b<0x80;b++)
            for(unsigned int c=0;c<0x80;c++)
                for(unsigned int d=0;d<0x80;d++) {
                    unsigned int i = (a<<24)|(b<<16)|(c<<8)|d; // calculate the value together
                    
                    // Give some regular updates to see progress speed 
                    if(i/0x10000000!=lastDiv) {
                        puts(".");
                        lastDiv = i/0x10000000;
                    }
                    
                    trySolve(i);
                }
}
