#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> 


uint32_t func_0000(uint32_t regA) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = regA;
    
    regs1 = regs0 >> 0x00000007;
    regs21 = regs0 >> 0x00000004;
    regs5 = regs0 >> 0x0000000B;
    regs20 = regs0 >> 0x0000000C;
    regs12 = regs0 >> 0x00000008;
    regs2 = regs0 >> 0x0000000F;
    regs17 = regs0 >> 0x00000003;
    regs18 = regs0 >> 0x00000006;
    regs9 = regs20 ^ regs12;
    regs10 = regs0 >> 0x0000000E;
    regs8 = regs5 ^ regs2;
    regs11 = regs0 >> 0x0000000A;
    regs5 = regs5 ^ regs1;
    regs12 = regs12 ^ regs21;
    regs4 = regs0 >> 0x00000002;
    regs7 = regs10 ^ regs11;
    regs12 = regs0 ^ regs12;
    regs10 = regs10 ^ regs18;
    regs5 = regs17 ^ regs5;
    regs12 = regs12 & 0x00000001;
    regs10 = regs4 ^ regs10;
    regs5 = regs5 << 0x0000000F;
    regs22 = regs0 >> 0x0000000D;
    regs19 = regs0 >> 0x00000009;
    regs5 = regs5 | regs12;
    regs10 = regs10 << 0x0000000E;
    regs12 = 0x00004000;
    regs3 = regs22 ^ regs19;
    regs16 = regs0 >> 0x00000001;
    regs10 = regs10 & regs12;
    regs5 = regs5 | regs10;
    regs10 = regs3 ^ regs16;
    regs12 = 0x00002000;
    regs10 = regs10 << 0x0000000D;
    regs10 = regs10 & regs12;
    regs5 = regs5 | regs10;
    regs10 = regs9 ^ regs21;
    regs12 = 0x00001000;
    regs10 = regs10 << 0x0000000C;
    regs10 = regs10 & regs12;
    regs5 = regs5 | regs10;
    regs12 = 0x00001000;
    regs10 = regs1 ^ regs8;
    regs12 = regs12 - 0x00000800;
    regs10 = regs10 << 0x0000000B;
    regs10 = regs10 & regs12;
    regs5 = regs5 | regs10;
    regs10 = regs18 ^ regs4;
    regs6 = regs0 >> 0x00000005;
    regs11 = regs11 ^ regs10;
    regs22 = regs22 ^ regs16;
    regs11 = regs11 << 0x0000000A;
    regs22 = regs6 ^ regs22;
    regs11 = regs11 & 0x00000400;
    regs9 = regs9 ^ regs0;
    regs22 = regs22 << 0x00000009;
    regs5 = regs5 | regs11;
    regs22 = regs22 & 0x00000200;
    regs9 = regs9 << 0x00000008;
    regs8 = regs17 ^ regs8;
    regs9 = regs9 & 0x00000100;
    regs5 = regs5 | regs22;
    regs8 = regs8 << 0x00000007;
    regs18 = regs18 ^ regs7;
    regs19 = regs19 ^ regs16;
    regs5 = regs5 | regs9;
    regs8 = regs8 & 0x000000FF;
    regs18 = regs18 << 0x00000006;
    regs19 = regs6 ^ regs19;
    regs20 = regs20 ^ regs21;
    regs5 = regs5 | regs8;
    regs18 = regs18 & 0x00000040;
    regs19 = regs19 << 0x00000005;
    regs0 = regs0 ^ regs20;
    regs5 = regs5 | regs18;
    regs19 = regs19 & 0x00000020;
    regs0 = regs0 << 0x00000004;
    regs5 = regs5 | regs19;
    regs0 = regs0 & 0x00000010;
    regs0 = regs5 | regs0;
    regs5 = regs1 ^ regs17;
    regs5 = regs2 ^ regs5;
    regs5 = regs5 << 0x00000003;
    regs4 = regs4 ^ regs7;
    regs5 = regs5 & 0x00000008;
    regs4 = regs4 << 0x00000002;
    regs3 = regs3 ^ regs6;
    regs0 = regs0 | regs5;
    regs4 = regs4 & 0x00000004;
    regs3 = regs3 << 0x00000001;
    regs0 = regs0 | regs4;
    regs3 = regs3 & 0x00000002;
    regs0 = regs0 | regs3;
    regs0 = regs0 << 0x00000010;
    regs0 = regs0 >> 0x00000010;
    
    return regs0;
}

uint32_t func_0192(uint32_t regA) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = regA;

    regs4 = regs0 >> 0x0000000F;
    regs7 = regs0 >> 0x0000000B;
    regs8 = regs0 >> 0x0000000C;
    regs21 = regs0 >> 0x00000008;
    regs20 = regs0 >> 0x00000007;
    regs6 = regs0 >> 0x00000006;
    regs12 = regs8 ^ regs21;
    regs22 = regs0 >> 0x00000004;
    regs11 = regs4 ^ regs7;
    regs13 = regs0 >> 0x0000000A;
    regs1 = regs0 >> 0x0000000E;
    regs19 = regs0 >> 0x00000002;
    regs18 = regs13 ^ regs1;
    regs5 = regs11 ^ regs20;
    regs14 = regs12 ^ regs22;
    regs13 = regs13 ^ regs6;
    regs16 = regs0 >> 0x00000005;
    regs9 = regs0 >> 0x0000000D;
    regs10 = regs0 >> 0x00000009;
    regs14 = regs14 & 0x00000001;
    regs5 = regs5 << 0x0000000F;
    regs13 = regs19 ^ regs13;
    regs3 = regs0 >> 0x00000001;
    regs17 = regs9 ^ regs10;
    regs5 = regs5 | regs14;
    regs9 = regs9 ^ regs16;
    regs14 = 0x00004000;
    regs13 = regs13 << 0x0000000E;
    regs13 = regs13 & regs14;
    regs9 = regs3 ^ regs9;
    regs5 = regs5 | regs13;
    regs9 = regs9 << 0x0000000D;
    regs13 = 0x00002000;
    regs9 = regs9 & regs13;
    regs12 = regs12 ^ regs0;
    regs2 = regs0 >> 0x00000003;
    regs5 = regs5 | regs9;
    regs12 = regs12 << 0x0000000C;
    regs9 = 0x00001000;
    regs12 = regs12 & regs9;
    regs11 = regs11 ^ regs2;
    regs9 = 0x00001000;
    regs9 = regs9 - 0x00000800;
    regs11 = regs11 << 0x0000000B;
    regs11 = regs11 & regs9;
    regs9 = regs6 ^ regs18;
    regs5 = regs5 | regs12;
    regs9 = regs9 << 0x0000000A;
    regs5 = regs5 | regs11;
    regs9 = regs9 & 0x00000400;
    regs5 = regs5 | regs9;
    regs9 = regs16 ^ regs3;
    regs10 = regs10 ^ regs9;
    regs8 = regs8 ^ regs22;
    regs8 = regs0 ^ regs8;
    regs10 = regs10 << 0x00000009;
    regs4 = regs4 ^ regs20;
    regs10 = regs10 & 0x00000200;
    regs8 = regs8 << 0x00000008;
    regs4 = regs2 ^ regs4;
    regs5 = regs5 | regs10;
    regs8 = regs8 & 0x00000100;
    regs4 = regs4 << 0x00000007;
    regs18 = regs19 ^ regs18;
    regs5 = regs5 | regs8;
    regs4 = regs4 & 0x000000FF;
    regs18 = regs18 << 0x00000006;
    regs16 = regs16 ^ regs17;
    regs21 = regs21 ^ regs22;
    regs5 = regs5 | regs4;
    regs18 = regs18 & 0x00000040;
    regs16 = regs16 << 0x00000005;
    regs0 = regs0 ^ regs21;
    regs5 = regs5 | regs18;
    regs16 = regs16 & 0x00000020;
    regs0 = regs0 << 0x00000004;
    regs5 = regs5 | regs16;
    regs0 = regs0 & 0x00000010;
    regs0 = regs5 | regs0;
    regs5 = regs7 ^ regs20;
    regs5 = regs2 ^ regs5;
    regs5 = regs5 << 0x00000003;
    regs5 = regs5 & 0x00000008;
    regs0 = regs0 | regs5;
    regs5 = regs6 ^ regs19;
    regs5 = regs1 ^ regs5;
    regs5 = regs5 << 0x00000002;
    regs3 = regs3 ^ regs17;
    regs5 = regs5 & 0x00000004;
    regs3 = regs3 << 0x00000001;
    regs0 = regs0 | regs5;
    regs3 = regs3 & 0x00000002;
    regs0 = regs0 | regs3;
    regs0 = regs0 << 0x00000010;
    regs0 = regs0 >> 0x00000010;
    
    return regs0;
}


void func_0545(uint32_t* regA, uint32_t* regB) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = *regA;
    regs1 = *regB;


    regs5 = regs1 >> 0x0000001C;
    regs5 = regs5 << 0x00000014;
    regs4 = regs1 >> 0x00000018;
    regs4 = regs4 & 0x0000000F;
    regs3 = regs1 >> 0x00000004;
    regs3 = regs3 << 0x0000001C;
    regs5 = regs5 | regs3;
    regs2 = regs0 << 0x00000008;
    regs3 = 0x00001000;
    regs3 = regs3 - 0x00000100;
    regs2 = regs2 & regs3;
    regs5 = regs5 | regs2;
    regs2 = regs1 >> 0x00000008;
    regs6 = 0x0000F000;
    regs2 = regs2 & regs6;
    regs4 = regs4 | regs2;
    regs2 = regs1 << 0x00000008;
    regs7 = 0x0F000000;
    regs2 = regs2 & regs7;
    regs4 = regs4 | regs2;
    regs2 = regs1 >> 0x00000008;
    regs2 = regs2 & 0x000000F0;
    regs5 = regs5 | regs2;
    regs2 = regs1 << 0x00000008;
    regs6 = 0x000F0000;
    regs2 = regs2 & regs6;
    regs5 = regs5 | regs2;
    regs2 = regs1 << 0x00000008;
    regs3 = regs3 & regs2;
    regs4 = regs4 | regs3;
    regs2 = regs1 << 0x00000004;
    regs3 = regs0 >> 0x0000001C;
    regs3 = regs3 | regs2;
    regs3 = regs3 << 0x00000014;
    regs2 = 0x00F00000;
    regs3 = regs3 & regs2;
    regs4 = regs4 | regs3;
    regs2 = regs0 >> 0x00000018;
    regs2 = regs2 & 0x0000000F;
    regs5 = regs5 | regs2;
    regs1 = regs1 << 0x0000000C;
    regs3 = regs0 >> 0x00000014;
    regs3 = regs3 | regs1;
    regs3 = regs3 << 0x0000000C;
    regs2 = 0x0000F000;
    regs3 = regs3 & regs2;
    regs5 = regs5 | regs3;
    regs1 = regs0 << 0x00000008;
    regs1 = regs1 & regs7;
    regs2 = regs0 >> 0x00000008;
    regs2 = regs2 & 0x000000F0;
    regs4 = regs4 | regs2;
    regs3 = regs0 << 0x00000008;
    regs3 = regs3 & regs6;
    regs4 = regs4 | regs3;
    regs0 = regs0 >> 0x00000004;
    regs0 = regs0 << 0x0000001C;
    regs0 = regs0 | regs4;
    regs1 = regs1 | regs5;

    *regA = regs0;
    *regB = regs1;
}

void func_0653(uint32_t* regA, uint32_t* regB) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = *regA;
    regs1 = *regB;

    regs5 = regs1 >> 0x0000001C;
    regs5 = regs5 << 0x00000014;
    regs4 = regs1 >> 0x00000004;
    regs4 = regs4 << 0x0000001C;
    regs5 = regs5 | regs4;
    regs2 = regs1 << 0x00000008;
    regs4 = regs0 >> 0x00000018;
    regs6 = regs1 >> 0x00000018;
    regs4 = regs4 & 0x0000000F;
    regs7 = regs0 << 0x00000008;
    regs3 = 0x00001000;
    regs3 = regs3 - 0x00000100;
    regs7 = regs7 & regs3;
    regs4 = regs4 | regs7;
    regs6 = regs6 & 0x0000000F;
    regs5 = regs5 | regs6;
    regs6 = regs1 >> 0x00000008;
    regs7 = 0x0000F000;
    regs6 = regs6 & regs7;
    regs4 = regs4 | regs6;
    regs17 = 0x0F000000;
    regs6 = regs2 & regs17;
    regs5 = regs5 | regs6;
    regs6 = regs1 >> 0x00000008;
    regs6 = regs6 & 0x000000F0;
    regs5 = regs5 | regs6;
    regs6 = 0x000F0000;
    regs7 = regs2 & regs6;
    regs4 = regs4 | regs7;
    regs3 = regs3 & regs2;
    regs5 = regs5 | regs3;
    regs2 = regs1 << 0x00000004;
    regs3 = regs0 >> 0x0000001C;
    regs3 = regs3 | regs2;
    regs3 = regs3 << 0x00000014;
    regs2 = 0x00F00000;
    regs3 = regs3 & regs2;
    regs4 = regs4 | regs3;
    regs1 = regs1 << 0x0000000C;
    regs3 = regs0 >> 0x00000014;
    regs3 = regs3 | regs1;
    regs3 = regs3 << 0x0000000C;
    regs2 = 0x0000F000;
    regs3 = regs3 & regs2;
    regs5 = regs5 | regs3;
    regs3 = regs0 << 0x00000008;
    regs3 = regs3 & regs17;
    regs4 = regs4 | regs3;
    regs3 = regs0 >> 0x00000008;
    regs3 = regs3 & 0x000000F0;
    regs4 = regs4 | regs3;
    regs1 = regs0 << 0x00000008;
    regs1 = regs1 & regs6;
    regs0 = regs0 >> 0x00000004;
    regs0 = regs0 << 0x0000001C;
    
    
    regs0 = regs0 | regs4;
    regs1 = regs1 | regs5;
    
    *regA = regs0;
    *regB = regs1;
}


void func_0387(uint32_t* regA, uint32_t* regB) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = *regA;
    regs1 = *regB;
    
    regs11 = regs0;
    regs0 = regs1 >> 0x00000010;
    regs0 = func_0000(regs0);
    regs10 = regs0;
    regs0 = regs1 << 0x00000010;
    regs0 = regs0 >> 0x00000010;
    regs0 = func_0192(regs0);
    regs9 = regs0;
    regs0 = regs11 >> 0x00000010;
    regs0 = func_0192(regs0);
    regs8 = regs0;
    regs0 = regs11 << 0x00000010;
    regs0 = regs0 >> 0x00000010;
    regs0 = func_0000(regs0);
    regs1 = regs8 >> 0x00000010;
    regs8 = regs8 << 0x00000010;
    regs0 = regs0 | regs8;
    regs5 = regs10 << 0x00000010;
    regs5 = regs9 | regs5;
    regs1 = regs5 | regs1;

    *regA = regs0;
    *regB = regs1;
}    

// 64bit shl
void func_0442_shl(uint32_t* regA, uint32_t* regB, uint32_t regC) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = *regA;
    regs1 = *regB;
    regs2 = regC;
    
    if(regs2 == 0) {
        return;
    }
    
    if(regs2 >= 0x40) {
        
        regs0 = 0;
        regs1 = 0;
        
        *regA = regs0;
        *regB = regs1;
        return;
    }
    
    if(regs2 >= 0x20) {
        regs8 = regs2 - 0x20;
        regs1 = regs0 << regs8;
        regs0 = 0;
        *regA = regs0;
        *regB = regs1;
        return;
    }
    
    regs8 = regs1 << regs2;
    regs10 = 0x20;
    regs10 = regs10 - regs2;
    regs9 = regs0 >> regs10;
    regs1 = regs8 | regs9;
    
    regs0 = regs0 << regs2;
    
    *regA = regs0;
    *regB = regs1;
}    
    
    

// 64bit shr
void func_0479_shr(uint32_t* regA, uint32_t* regB, uint32_t regC) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = *regA;
    regs1 = *regB;
    regs2 = regC;
    
    if(regs2 == 0) {
        return;
    }
    
    if(regs2 >= 0x40) {
        
        regs0 = 0;
        regs1 = 0;
        
        *regA = regs0;
        *regB = regs1;
        
        return;
    }
    
    if(regs2 >= 0x20) {
        regs8 = regs2 - 0x20;
        regs0 = regs1 >> regs8;
        regs1 = 0;
        
        *regA = regs0;
        *regB = regs1;
        return;
    }
    
    regs8 = regs0 >> regs2;
    regs10 = 0x20;
    regs10 = regs10 - regs2;
    regs9 = regs1 << regs10;
    regs0 = regs8 | regs9;
    regs1 = regs1 >> regs2;
    
    
    *regA = regs0;
    *regB = regs1;
}    

uint32_t SBOX1[] = {
 0x00000004, 0x00000007, 0x00000002, 0x00000001,  
 0x00000008, 0x0000000B, 0x0000000E, 0x0000000D,
 0x0000000F, 0x0000000C, 0x00000009, 0x0000000A,  
 0x00000003, 0x00000000, 0x00000005, 0x00000006
};
 
uint32_t SBOX2[] = {
 0x0000000D, 0x00000003, 0x00000002, 0x0000000C,  
 0x00000000, 0x0000000E, 0x0000000F, 0x00000001,
 0x00000004, 0x0000000A, 0x0000000B, 0x00000005,  
 0x00000009, 0x00000007, 0x00000006, 0x00000008
 };


void func_0516_nibble_sbox(uint32_t* regA, uint32_t* regB, uint32_t* SBOX) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = *regA;
    regs1 = *regB;
    
    regs14 = regs0;
    regs15 = regs1;
    regs8 = 0x00000000;
    regs10 = 0x00000000;
    regs9 = 0x00000000;
    regs11 = 0x00000040;
    
    do {
        regs2 = regs8;
        regs0 = regs14;
        regs1 = regs15;
        func_0479_shr(&regs0, &regs1, regs2);
        regs0 = regs0 & 0x0000000F;
        regs0 = SBOX[regs0];
        regs2 = regs8;
        regs1 = 0x00000000;
        func_0442_shl(&regs0, &regs1, regs2);
        regs8 = regs8 + 0x00000004;
        regs10 = regs10 | regs0;
        regs9 = regs9 | regs1;
    }while(regs8 != regs11);
    regs0 = regs10;
    regs1 = regs9;

    *regA = regs0;
    *regB = regs1;
}    



void func_0759(uint32_t* regA, uint32_t* regB, uint32_t flagC, uint32_t flagD) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    
    regs0 = *regA;
    regs1 = *regB;
    
    // Rounds SBOX1 

    regs0 = (regs0 ^ 0x4C414355) ^ flagC;
    regs1 = (regs1 ^ 0x43415241) ^ flagD;
    
    
    func_0516_nibble_sbox(&regs0, &regs1, SBOX1);
    func_0387(&regs0, &regs1);
    func_0545(&regs0, &regs1);
    regs0 = (0x4C414355 ^ regs0) ^ 0x03707344;
    regs1 = (0x43415241 ^ regs1) ^ 0x13198A2E;
    
    func_0516_nibble_sbox(&regs0, &regs1, SBOX1);
    func_0387(&regs0, &regs1);
    func_0545(&regs0, &regs1);
    regs0 = (0x4C414355 ^ regs0) ^ 0x299F31D0;
    regs1 = (0x43415241 ^ regs1) ^ 0xA4093822;
    
    func_0516_nibble_sbox(&regs0, &regs1, SBOX1);
    func_0387(&regs0, &regs1);
    func_0545(&regs0, &regs1);
    regs0 = (regs0 ^ 0x4C414355) ^ 0xEC4E6C89;
    regs1 = (regs1 ^ 0x43415241) ^ 0x082EFA98;
    
    func_0516_nibble_sbox(&regs0, &regs1, SBOX1);
    func_0387(&regs0, &regs1);
    func_0545(&regs0, &regs1);
    regs0 = (0x4C414355 ^ regs0) ^ 0x38D01377;
    regs1 = (0x43415241 ^ regs1) ^ 0x452821E6;
    
    func_0516_nibble_sbox(&regs0, &regs1, SBOX1);
    func_0387(&regs0, &regs1);
    func_0545(&regs0, &regs1);
    regs0 = (0x4C414355 ^ regs0) ^ 0x34E90C6C;
    regs1 = (0x43415241 ^ regs1) ^ 0xBE5466CF;
    
    
    // Transition
    
    func_0516_nibble_sbox(&regs0, &regs1, SBOX1);
    func_0387(&regs0, &regs1);
    func_0516_nibble_sbox(&regs0, &regs1, SBOX2);
    
    
    // Rounds SBOX2
    
    regs0 = (0x4C414355 ^ regs0) ^ 0xFD955CB1;
    regs1 = (0x43415241 ^ regs1) ^ 0x7EF84F78;
    func_0653(&regs0, &regs1);
    func_0387(&regs0, &regs1);
    func_0516_nibble_sbox(&regs0, &regs1, SBOX2);
    
    regs0 = (0x4C414355 ^ regs0) ^ 0xF1AC43AA;
    regs1 = (0x43415241 ^ regs1) ^ 0x85840851;
    func_0653(&regs0, &regs1);
    func_0387(&regs0, &regs1);
    func_0516_nibble_sbox(&regs0, &regs1, SBOX2);
    
    regs0 = (0x4C414355 ^ regs0) ^ 0x25323C54;
    regs1 = (regs1 ^ 0x43415241) ^ 0xC882D32F;
    func_0653(&regs0, &regs1);
    func_0387(&regs0, &regs1);
    func_0516_nibble_sbox(&regs0, &regs1, SBOX2);
    
    regs0 = (0x4C414355 ^ regs0) ^ 0xE0E3610D;
    regs1 = (0x43415241 ^ regs1) ^ 0x64A51195;
    func_0653(&regs0, &regs1);
    func_0387(&regs0, &regs1);
    func_0516_nibble_sbox(&regs0, &regs1, SBOX2);

    regs0 = (0x4C414355 ^ regs0) ^ 0xCA0C2399;
    regs1 = (0x43415241 ^ regs1) ^ 0xD3B5A399;
    func_0653(&regs0, &regs1);
    func_0387(&regs0, &regs1);
    func_0516_nibble_sbox(&regs0, &regs1, SBOX2);
    

    regs11 = flagD << 0x0000001F;
    regs16 = flagC >> 0x00000001;
    regs2 = regs11 | regs16;
    regs10 = flagC << 0x0000001F;
    regs17 = flagD >> 0x00000001;
    regs18 = regs10 | regs17;
    
    regs8 = 0x43415241 ^ regs1;
    regs0 = regs2 ^ (0x4C414355 ^ regs0);
    regs12 = flagD >> 0x0000001F;
    regs0 = (regs0 ^ regs12) ^ 0xC97C50DD;
    regs1 = (regs18 ^ regs8) ^ 0xC0AC29B7;

    *regA = regs0;
    *regB = regs1;
}


void func_0759i(uint32_t* regA, uint32_t* regB, uint32_t flagC, uint32_t flagD) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = *regA;
    regs1 = *regB;
    
    regs0 = ((flagD << 0x0000001F) | (flagC >> 0x00000001)) ^ (0x4C414355 ^ regs0);
    regs0 = (regs0 ^ (flagD >> 0x0000001F)) ^ 0xC97C50DD;
    regs1 = (((flagC << 0x0000001F) | (flagD >> 0x00000001)) ^ (0x43415241 ^ regs1)) ^ 0xC0AC29B7;
    
    // Rounds SBOX2

    uint32_t xl0[] = {0xCA0C2399, 0xE0E3610D, 0x25323C54, 0xF1AC43AA, 0xFD955CB1};
    uint32_t xr0[] = {0xD3B5A399, 0x64A51195, 0xC882D32F, 0x85840851, 0x7EF84F78};
    
    for(int i=0;i<5;i++) {
        func_0516_nibble_sbox(&regs0, &regs1, SBOX1);
        func_0387(&regs0, &regs1);
        
        func_0653(&regs0, &regs1);
        func_0653(&regs0, &regs1);
        func_0653(&regs0, &regs1);
        func_0653(&regs0, &regs1);
        func_0653(&regs0, &regs1);
        func_0653(&regs0, &regs1);
        func_0653(&regs0, &regs1);
        
        regs0 = (0x4C414355 ^ regs0) ^ xl0[i];
        regs1 = (0x43415241 ^ regs1) ^ xr0[i];
    }

    // Transition
    func_0516_nibble_sbox(&regs0, &regs1, SBOX1);
    func_0387(&regs0, &regs1);
    func_0516_nibble_sbox(&regs0, &regs1, SBOX2);
    

    uint32_t xl1[] = {0x34E90C6C, 0x38D01377, 0xEC4E6C89, 0x299F31D0,  0x03707344};
    uint32_t xr1[] = {0xBE5466CF, 0x452821E6, 0x082EFA98, 0xA4093822,  0x13198A2E};
    
    for(int i=0;i<5;i++) {
        
        regs0 = (0x4C414355 ^ regs0) ^ xl1[i];
        regs1 = (0x43415241 ^ regs1) ^ xr1[i];
        
        func_0545(&regs0, &regs1);
        func_0545(&regs0, &regs1);
        func_0545(&regs0, &regs1);
        func_0545(&regs0, &regs1);
        func_0545(&regs0, &regs1);
        func_0545(&regs0, &regs1);
        func_0545(&regs0, &regs1);
        
        func_0387(&regs0, &regs1);
        func_0516_nibble_sbox(&regs0, &regs1, SBOX2);

    }
    
    regs0 = (regs0 ^ 0x4C414355) ^ flagC;
    regs1 = (regs1 ^ 0x43415241) ^ flagD;
    
    
    *regA = regs0;
    *regB = regs1;
}



uint32_t a_out = 0;
uint32_t b_out = 0;

uint32_t c = 0;
uint32_t d = 0;

void main(int argc, void** argv) {
    
    if(argc != 5) {
        return;
    }
    
    a_out = atoi(argv[1]);
    b_out = atoi(argv[2]);
    
    c = atoi(argv[3]);
    d = atoi(argv[4]);
    
    func_0759(&a_out, &b_out, c, d);
    printf("0x%08X%08X\n", b_out, a_out);
}
