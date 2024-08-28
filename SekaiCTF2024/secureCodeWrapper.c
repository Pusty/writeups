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
    
    /*
    // Block 1
    r13 = x;
    r15 = y;
    #include "secureCodeBlock1.c"
    */
    
    /*
    // Block 2
    rdi = x;
    rsi = y;
    #include "secureCodeBlock2.c"
    */
    
    /*
    // Block 3
    rbp = x;
    r13 = y;
    #include "secureCodeBlock3.c"
    */
    
    /*
    // Block 4
    r14 = x;
    rdi = y;
    #include "secureCodeBlock4.c"
    */
    
    /*
    // Block 5
    rsi = x;
    r12 = y;
    #include "secureCodeBlock5.c"
    */
    
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