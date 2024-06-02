#include <stdint.h>
#include <stdio.h>


void func_0000(uint32_t* regA, uint32_t* regB) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = *regA;
    regs1 = *regB;
    
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
    
    *regA = regs0;
    *regB = regs1;
}

void func_0192(uint32_t* regA, uint32_t* regB) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = *regA;
    regs1 = *regB;

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
    
    *regA = regs0;
    *regB = regs1;
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
    uint32_t tmp = regs1;
    func_0000(&regs0, &tmp);
    regs10 = regs0;
    regs0 = regs1 << 0x00000010;
    regs0 = regs0 >> 0x00000010;
    func_0192(&regs0, &regs1);
    regs9 = regs0;
    regs0 = regs11 >> 0x00000010;
    func_0192(&regs0, &regs1);
    regs8 = regs0;
    regs0 = regs11 << 0x00000010;
    regs0 = regs0 >> 0x00000010;
    func_0000(&regs0, &regs1);
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
    
    // L0442
    if(regs2 == 0) {
        return;
    }
    
    // L0445
    if(regs2 >= 0x40) {
        
        regs0 = 0;
        regs1 = 0;
        
        *regA = regs0;
        *regB = regs1;
        return;
    }
    
    // L0450
    if(regs2 >= 0x20) {
        // L0469
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

// Hardcoded SBoxes
uint32_t memory[] = {
 0x00000004, 0x00000007, 0x00000002, 0x00000001,  
 0x00000008, 0x0000000B, 0x0000000E, 0x0000000D,
 0x0000000F, 0x0000000C, 0x00000009, 0x0000000A,  
 0x00000003, 0x00000000, 0x00000005, 0x00000006, 
 0x0000000D, 0x00000003, 0x00000002, 0x0000000C,  
 0x00000000, 0x0000000E, 0x0000000F, 0x00000001,
 0x00000004, 0x0000000A, 0x0000000B, 0x00000005,  
 0x00000009, 0x00000007, 0x00000006, 0x00000008
 };

void func_0516(uint32_t* regA, uint32_t* regB, uint32_t regC) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = *regA;
    regs1 = *regB;
    regs2 = regC;
    
    regs14 = regs0;
    regs15 = regs1;
    regs12 = regs2;
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
        regs0 = regs0 + regs12;
        regs0 = memory[regs0];
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



void func_0759(uint32_t* regA, uint32_t* regB, uint32_t regC, uint32_t regD, uint32_t regE, uint32_t regF) {
    uint32_t regs0, regs1, regs2, regs3, regs4, regs5, regs6, regs7, regs8, regs9, regs10, regs11, regs12, regs13, regs14, regs15, regs16, regs17, regs18, regs19, regs20, regs21, regs22;
    
    regs0 = 0;
    regs1 = 0;
    regs2 = 0;
    regs3 = 0;
    regs4 = 0;
    regs5 = 0;
    regs6 = 0;
    regs7 = 0;
    
    regs8 = 0;
    regs9 = 0;
    regs10 = 0;
    regs11 = 0;
    regs12 = 0;
    regs13 = 0;
    regs14 = 0;
    regs15 = 0;
    
    regs16 = 0;
    regs17 = 0;
    regs18 = 0;
    regs19 = 0;
    regs20 = 0;
    regs21 = 0;
    regs22 = 0;
    
    regs0 = *regA;
    regs1 = *regB;
    
    regs2 = regC; // flag Input
    regs3 = regD; // flag Input
    
    
    regs4 = regE;
    regs5 = regF;
    
    regs10 = regs2;
    regs12 = regs3;
    regs9 = regs4;
    regs8 = regs5;
    regs0 = regs0 ^ regs4;
    regs1 = regs1 ^ regs5;
    regs0 = regs0 ^ regs10;
    regs1 = regs1 ^ regs3;
    regs2 = 0x00000000;
    func_0516(&regs0, &regs1, regs2);
    func_0387(&regs0, &regs1);
    func_0545(&regs0, &regs1);
    regs16 = regs9 ^ regs0;
    regs17 = regs8 ^ regs1;
    regs0 = regs16 ^ 0x03707344;
    regs1 = regs17 ^ 0x13198A2E;
    func_0516(&regs0, &regs1, regs2);
    func_0387(&regs0, &regs1);
    func_0545(&regs0, &regs1);
    regs6 = regs9 ^ regs0;
    regs7 = regs8 ^ regs1;
    regs0 = regs6 ^ 0x299F31D0;
    regs1 = regs7 ^ 0xA4093822;
    regs2 = 0x00000000;
    func_0516(&regs0, &regs1, regs2);
    func_0387(&regs0, &regs1);
    func_0545(&regs0, &regs1);
    regs0 = regs0 ^ regs9;
    regs1 = regs1 ^ regs8;
    regs0 = regs0 ^ 0xEC4E6C89;
    regs1 = regs1 ^ 0x082EFA98;
    regs2 = 0x00000000;
    func_0516(&regs0, &regs1, regs2);
    func_0387(&regs0, &regs1);
    func_0545(&regs0, &regs1);
    regs3 = regs9 ^ regs0;
    regs4 = regs8 ^ regs1;
    regs0 = regs3 ^ 0x38D01377;
    regs1 = regs4 ^ 0x452821E6;
    regs2 = 0x00000000;
    func_0516(&regs0, &regs1, regs2);
    func_0387(&regs0, &regs1);
    func_0545(&regs0, &regs1);
    regs21 = regs9 ^ regs0;
    regs22 = regs8 ^ regs1;
    regs0 = regs21 ^ 0x34E90C6C;
    regs1 = regs22 ^ 0xBE5466CF;
    regs2 = 0x00000000;
    func_0516(&regs0, &regs1, regs2);
    func_0387(&regs0, &regs1);
    regs2 = 0x00000010;
    func_0516(&regs0, &regs1, regs2);
    regs2 = regs9 ^ regs0;
    regs17 = regs8 ^ regs1;
    regs0 = regs2 ^ 0xFD955CB1;
    regs1 = regs17 ^ 0x7EF84F78;
    func_0653(&regs0, &regs1);
    func_0387(&regs0, &regs1);
    regs2 = 0x00000010;
    func_0516(&regs0, &regs1, regs2);
    regs6 = regs9 ^ regs0;
    regs7 = regs8 ^ regs1;
    regs0 = regs6 ^ 0xF1AC43AA;
    regs1 = regs7 ^ 0x85840851;
    func_0653(&regs0, &regs1);
    func_0387(&regs0, &regs1);
    regs2 = 0x00000010;
    func_0516(&regs0, &regs1, regs2);
    regs13 = regs9 ^ regs0;
    regs1 = regs1 ^ regs8;
    regs0 = regs13 ^ 0x25323C54;
    regs1 = regs1 ^ 0xC882D32F;
    func_0653(&regs0, &regs1);
    func_0387(&regs0, &regs1);
    regs2 = 0x00000010;
    func_0516(&regs0, &regs1, regs2);
    regs18 = regs9 ^ regs0;
    regs3 = regs8 ^ regs1;
    regs0 = regs18 ^ 0xE0E3610D;
    regs1 = regs3 ^ 0x64A51195;
    func_0653(&regs0, &regs1);
    func_0387(&regs0, &regs1);
    regs2 = 0x00000010;
    func_0516(&regs0, &regs1, regs2);
    regs19 = regs9 ^ regs0;
    regs20 = regs8 ^ regs1;
    regs0 = regs19 ^ 0xCA0C2399;
    regs1 = regs20 ^ 0xD3B5A399;
    func_0653(&regs0, &regs1);
    func_0387(&regs0, &regs1);
    regs2 = 0x00000010;
    func_0516(&regs0, &regs1, regs2);
    regs11 = regs12 << 0x0000001F;
    regs16 = regs10 >> 0x00000001;
    regs2 = regs11 | regs16;
    regs10 = regs10 << 0x0000001F;
    regs17 = regs12 >> 0x00000001;
    regs18 = regs10 | regs17;
    regs9 = regs9 ^ regs0;
    regs8 = regs8 ^ regs1;
    regs0 = regs2 ^ regs9;
    regs3 = regs18 ^ regs8;
    regs12 = regs12 >> 0x0000001F;
    regs4 = regs0 ^ regs12;
    regs0 = regs4 ^ 0xC97C50DD;
    regs1 = regs3 ^ 0xC0AC29B7;

    *regA = regs0;
    *regB = regs1;
}

uint32_t a_in = 0xD5DB2C94;
uint32_t b_in = 0x959DB87D;

uint32_t a_out = 0;
uint32_t b_out = 0;


uint32_t c = 0x67617465; // this will flag characters
uint32_t d = 0x636F6465; // flag characters

void main() {
    
    a_out = a_in;
    b_out = b_in;
    printf("%08X %08X =>\n", a_out, b_out);
    func_0759(&a_out, &b_out, c, d, 0x4C414355, 0x43415241);
    printf("%08X %08X <=\n", a_out, b_out);
}



