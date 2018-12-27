#include <stdio.h>
#include <stdlib.h>
#include <string.h>

short* base_address;
long filelen;

void dumpFile(char* name) {
    FILE *fileptr; 
    fileptr = fopen(name,"wb");
    fwrite(base_address,filelen,sizeof(char),fileptr);
    fclose(fileptr);
}

int logM = 0;
int count = 0;
short taintArray[0xFFFF];
//int marray[] = {0x36BE, 0x36C0, 0x3794, 0x3796, 0x37A2, 0x37AA, 0x37AC, 0x37AE, 0x37B0, 0x37B2, 0x37B4, 0x37B6, 0x37D4, 0x37D6, 0x38CC, 0x38D8, 0x38DA, 0x3962, 0x3982, 0x3984, 0x39B8, 0x39DE, 0x39E0, 0x39FE, 0x3A00, 0x3A0C, 0x3A0E, 0x3A2C, 0x3A2E, 0x3B02, 0x3B04, 0x3B10, 0x3B18, 0x3B1A, 0x3B1C, 0x3B1E, 0x3B20, 0x3B22, 0x3B24, 0x3B42, 0x3B44, 0x3C3A, 0x3C46, 0x3C48, 0x3C9C, 0x3C9E, 0x3CB6, 0x3CB8, 0x3CC4, 0x3D42, 0x3D44, 0x3D98, 0x3D9A, 0x3DEE, 0x3DF0, 0x3E44, 0x3E46, 0x3E9A, 0x3E9C, 0x3F02, 0x3F04, 0x3FD8, 0x3FDA, 0x3FE6, 0x3FEE, 0x3FF0, 0x3FF2, 0x3FF4, 0x3FF6, 0x3FF8, 0x3FFA, 0x4018, 0x401A, 0x4110, 0x411C, 0x411E, 0x41C2, 0x41C4, 0x41D0, 0x41D8, 0x41DA, 0x41DC, 0x41DE, 0x41E0, 0x41E2, 0x41E4, 0x4202, 0x4204, 0x4318, 0x4342, 0x4344, 0x4346, 0x43EA, 0x43EC, 0x43F8, 0x4400, 0x4402, 0x4404, 0x4406, 0x4408, 0x440A, 0x440C, 0x442A, 0x442C, 0x4540, 0x456A, 0x456C, 0x456E, 0x465A, 0x465C, 0x4668, 0x4670, 0x4672, 0x4674, 0x4676, 0x4678, 0x467A, 0x467C, 0x469A, 0x469C, 0x47A4, 0x47A6, 0x484A, 0x484C, 0x4858, 0x4860, 0x4862, 0x4864, 0x4866, 0x4868, 0x486A, 0x486C, 0x488A, 0x488C, 0x4982, 0x498E, 0x499A, 0x499C, 0x49BA, 0x49BC, 0x4A7E, 0x4A80, 0x4A8C, 0x4A94, 0x4A96, 0x4A98, 0x4A9A, 0x4A9C, 0x4A9E, 0x4AA0, 0x4ABE, 0x4AC0, 0x4BC8, 0x4BCA, 0x4C6E, 0x4C70, 0x4C7C, 0x4C84, 0x4C86, 0x4C88, 0x4C8A, 0x4C8C, 0x4C8E, 0x4C90, 0x4CAE, 0x4CB0, 0x4DA6, 0x4DB2, 0x4DBE, 0x4DC0, 0x4DCC, 0x4DCE, 0x4DD0, 0x4DD2, 0x4DD4, 0x4DD6, 0x4DD8, 0x4DDA, 0x4DDC, 0x4DDE, 0x4E08, 0x4E32, 0x4EA4, 0x4EA6, 0x4F06, 0x4F08, 0x4F20, 0x4F22, 0x4F76, 0x4F78, 0x4F90, 0x4F92, 0x4FAA, 0x4FAC, 0x4FB8, 0x500C, 0x500E, 0x504E, 0x512A, 0x512C, 0x5138, 0x5140, 0x5142, 0x5144, 0x5146, 0x5148, 0x514A, 0x514C, 0x516A, 0x516C, 0x5274, 0x5276, 0x531A, 0x531C, 0x5328, 0x5330, 0x5332, 0x5334, 0x5336, 0x5338, 0x533A, 0x533C, 0x535A, 0x535C, 0x5452, 0x546A, 0x546C, 0x54A2, 0x54A4, 0x54B0, 0x55B4, 0x55B6, 0x55C2, 0x55CA, 0x55CC, 0x55CE, 0x55D0, 0x55D2, 0x55D4, 0x55D6, 0x55F4, 0x55F6, 0x56FE, 0x5700, 0x57A4, 0x57A6, 0x57B2, 0x57BA, 0x57BC, 0x57BE, 0x57C0, 0x57C2, 0x57C4, 0x57C6, 0x57E4, 0x57E6, 0x58DC, 0x58F4, 0x58F6, 0x5902, 0x5904, 0x5910, 0x594E, 0x5950, 0x5990, 0x59C2, 0x59D0, 0x5AC8,0x5ACA};
int marray[] = {/*0x38DA, *//* 0x5990*/ /*0x12A0*/ 0x1B14}; //0x38DA = skips calculations, 0x5990 = final decision value over result (needs to be 0)
//int marray[] = {};
//1C6A,1C94,1BF4,1BE6

unsigned short readValueIndex = 0;
unsigned short readValue = 0;

unsigned short readValueState = 0;
unsigned short readValueIndexA = 0;
unsigned short readValueA = 0;
unsigned short readValueIndexB = 0;
unsigned short readValueB = 0;

unsigned short lastInst = 0;


int evaluateSubleqInstruction(short* base_data, unsigned short instp,  unsigned short word1, unsigned short word2, unsigned short word3) {
    int offsetA = ((int)word1)*2;
    int offsetB = ((int)word2)*2;

    //DEBUG
    if((offsetA >= 0x1207 && offsetA <= 0x1257)  || (offsetB >= 0x1207 && offsetB <= 0x1257)) {
        printf("#{%04X}: [%04X]@%04X = [%04X]@%04X - [%04X]@%04X\n", (instp*2)&0xFFFF, (base_data[word2] - base_data[word1])&0xFFFF,offsetB&0xFFFF, base_data[word2]&0xFFFF,offsetB&0xFFFF, base_data[word1]&0xFFFF,offsetA&0xFFFF); 
       // printf("#> %04X = '%04X'\n",((base_data[0xa66>>1]+1)&0xFFFF)*2 ,base_data[base_data[0xa66>>1]&0xFFFF+1]&0xFFFF);
        //printf("reading password char %02X @ %02X %02X = '%02X'\n",offset, instp, instp*2, base_data[word1]);
        //dumpFile("tmp.bin");
       // exit(0);
    } 
    if(instp*2 == 0x3e6) {
        //printf("dref_1 = %04X \n", (base_data[0x302>>1]&0xFFFF)<<1);
    }
    if(instp*2 == 0xa34) {
        printf("dref_1 = %04X \n", (base_data[0x302>>1]&0xFFFF)<<1);
        printf("value_0 = %04X \n", (base_data[0x290>>1]&0xFFFF)<<1);
        puts("!!!");
    }
    
    if((base_data[0x302>>1]&0xFFFF)<<1 ==  0x22CA) {
       // printf("dref_1 = %04X \n", (base_data[0x302>>1]&0xFFFF)<<1);
      //  printf("value_4 = %04X \n", (base_data[4>>1]&0xFFFF));
        //dumpFile("tmp.bin");
    }
    
    //DEBUG
    
        //TAINT CODE
    /*if(offsetA == 0x1208) { count++; logM = 1; }
    if(count >= 3 && count < 1000 && logM) {
      //  for(int i=0;i<(0x50/2);i++)
       //     taintArray[0x1208+2*i] = 1;
        //taintArray[0x5990] = 1;
        taintArray[0x1208+2*0] = 1;
        if(taintArray[offsetA] >= 1) {
            if(offsetA == offsetB) {
                if(taintArray[offsetA] == 1) {
                 //  printf("[!] Remove %04X\n", offsetA);
                }
                taintArray[offsetA] = -1;
            } else {
              //  if(taintArray[offsetB] >= 0) {
                    //if(taintArray[offsetA] < 0x1000)
                     // if(offsetB != 0xFE8)
                        printf("[!] Taint  {%04X} %04X@%04X - %04X@%04X = %04X [%04X]\n", offsetB, base_data[word2]&0xFFFF,offsetB, base_data[word1]&0xFFFF,offsetA,(base_data[word2]-base_data[word1])&0xFFFF, taintArray[offsetA]);
             //   }
                if(taintArray[offsetB] <= 0)
                    taintArray[offsetB] = taintArray[offsetA]+1;
                
              //  if(offsetB == 0) {
             //       printf("[!] Taint  {%04X} %04X@%04X - %04X@%04X = %04X [%04X]\n", offsetB, base_data[word2]&0xFFFF,offsetB, base_data[word1]&0xFFFF,offsetA,(base_data[word2]-base_data[word1])&0xFFFF, taintArray[offsetA]);
               
                  // printf("[!] Taint  %04X = '%04X' (by %04X)\n", offsetB, base_data[word2]&0xFFFF, offsetA);
            //    }
            }
        }
    }*/
    if(offsetA == 0x1208) { count++; logM = 1; }
    if(/*count >= 3 && count < 1000 && logM*/ 1) {
      //if(instp*2 == 0x3a4)
      //  puts("Next Instruction:");
      //if(offsetB == 0xFEE)
      //    printf("tmp = %04X\n", (base_data[word2] - base_data[word1])&0xFFFF);
      //if(offsetA == 0xC8E)
      //    puts("increasing by one");
      if(instp*2 == 0x410 ) lastInst = base_data[0x302>>1]&0xFFFF;
      
      
      //if(instp*2 == 0xf92) {
      //    printf("Set position from %04X to %04X [%04X]\n", lastInst,  base_data[0xfec>>1]&0xFFFF, instp*2);
      //}
     // if(instp*2 == 0xf18)
      //    printf("Branch repos\n"); //maybe something like a don't jump condition?
      
      if(offsetA != offsetB && instp*2 != 0x454 && instp*2 != 0xB4A) //offsetA >= 0x1000 || 
        if(offsetB >= 0x1000) {
            if(readValue == ((base_data[word2]-base_data[word1])&0xFFFF) && readValueIndex == offsetB) {
                //skip this one
            }else if(readValue != ((base_data[word2]-base_data[word1])&0xFFFF) && readValueIndex == offsetB) {
                unsigned short delta = (base_data[word2]-base_data[word1])&0xFFFF;
                delta = delta - readValue;
                if((delta&0xFFFF) == (readValueA&0xFFFF))
                     printf("{%08X} Added   %04X@%04X + %04X@%04X  = %04X\n", lastInst, readValue,offsetB,readValueA,readValueIndexA,(base_data[word2]-base_data[word1])&0xFFFF);
                else if((delta&0xFFFF) == (readValueB&0xFFFF))
                     printf("{%08X} Added   %04X@%04X + %04X@%04X  = %04X\n", lastInst, readValue,offsetB,readValueB,readValueIndexB,(base_data[word2]-base_data[word1])&0xFFFF);
                else if((delta&0xFFFF) == ((-readValueA)&0xFFFF))
                     printf("{%08X} Added   %04X@%04X - %04X@%04X  = %04X\n", lastInst, readValue,offsetB,readValueA,readValueIndexA,(base_data[word2]-base_data[word1])&0xFFFF);
                else if((delta&0xFFFF) == ((-readValueB)&0xFFFF))
                     printf("{%08X} Added   %04X@%04X - %04X@%04X  = %04X\n", lastInst, readValue,offsetB,readValueB,readValueIndexB,(base_data[word2]-base_data[word1])&0xFFFF);
                else
                     printf("{%08X} Changed %04X@%04X + %04X       = %04X\n", lastInst, readValue,offsetB,delta&0xFFFF,(base_data[word2]-base_data[word1])&0xFFFF);
            }else
                     printf("{%08X} Set     %04X@%04X = %04X\n", lastInst, base_data[word2]&0xFFFF,offsetB,(base_data[word2]-base_data[word1])&0xFFFF);
            
            readValueIndex = 0;
            readValue = 0;
        }
        else if(offsetA >= 0x1000) {
                if(offsetA == 0x5990)
                printf("{%04X} Reading %04X@%04X\n", instp*2, base_data[word1]&0xFFFF,offsetA);
                if(readValueState == 0) {
                   readValueIndexA = offsetA;
                   readValueA = base_data[word1]&0xFFFF;
                   readValueState = 1;
                }else if(readValueState == 1) {
                   readValueIndexB = offsetA;
                   readValueB = base_data[word1]&0xFFFF;
                   readValueState = 0;
                } 
               readValueIndex = offsetA;
               readValue = base_data[word1]&0xFFFF;
        }
    }
    
   //if((base_data[word2]&0xFFFF) == 0xB0FA || (base_data[word1]&0xFFFF) == 0xB0FA)
   //  printf("!{%04X}: [%04X]@%04X = [%04X]@%04X - [%04X]@%04X\n", (instp*2)&0xFFFF, (base_data[word2] - base_data[word1])&0xFFFF,offsetB&0xFFFF, base_data[word2]&0xFFFF,offsetB&0xFFFF, base_data[word1]&0xFFFF,offsetA&0xFFFF); 
       
    
    short sub_values = base_data[word2] - base_data[word1];
    base_data[word2] = sub_values;
    
    //base_data[0x2408/2] = 0; //this prevents all printing code
    

    if(word2 != 0/* && base_data[word2] != 0 && logM*/)
        for(int i=0;i<sizeof(marray);i++) {
            if(marray[i] == offsetB) {
                 printf("replaced %04X [%04X]\n", marray[i], base_data[word2]&0xFFFF);
                 if(marray[i] == 0x5990) {
                  //   base_data[word2] = 0x4a6;
                  if(base_data[word2] == 0x153) base_data[word2] = 0x666;
                 }else
                     base_data[word2] = 1;
                 count = 3;
                 logM = 1;
                 break;
            }
   }
        
    if(word3 == 0) return 0;
    if(sub_values <= 0) return 1;
    return 0;
}

unsigned long vmCode(short* base_data, unsigned short offset_max, unsigned short init_offset) {
    unsigned short instp = init_offset;
    unsigned long executed = -1;
    while(instp+3 < offset_max) {
        executed++;
        int shouldJump = evaluateSubleqInstruction(base_data,instp,base_data[instp],base_data[instp+1],base_data[instp+2]);
        if(shouldJump == 1)  {
            unsigned short dest = base_data[instp+2];
            if(dest == 0xFFFF) return executed;
            instp = dest;
        }else
            instp += 3;
        if(base_data[4] == 0) continue;
       // putchar(base_data[2]);
        printf("Print char: '%c'\n", base_data[2]);
        //logM = 0;
        base_data[4] = 0;
        base_data[2] = 0;
    }
    return executed;
}

void main() {
    FILE *fileptr;
    short* buffer;
    fileptr = fopen("BEFORE_EXECUTION.bin", "rb");
    fseek(fileptr, 0, SEEK_END);
    filelen = ftell(fileptr);
    rewind(fileptr);
    buffer = (short *)malloc((filelen+1)*sizeof(char));
    fread(buffer, filelen, 1, fileptr);
    fclose(fileptr);
    
    
    unsigned long highest = 0L;
    unsigned char highestChar = 0L;
    for(int c1=0x42;c1<0x7F;c1++) {
        for(int c2=0x45;c2<0x7F;c2++) {
            for(int i=0;i<0xFFFF;i++)
                taintArray[i] = 0;
            unsigned char* copy_buffer = (unsigned char*)malloc((filelen+1)*sizeof(char));
            memcpy(copy_buffer, buffer, (filelen+1)*sizeof(char));
            base_address = (short*)copy_buffer;
            /* OVERWRITE THE INPUT DATA */
            char* overwrite = "bum(H  Q k}wV~Lk?m1H@/>7=//>E ;?";//bum(H  Q k}wV~Lk?m1H@/>7=//>E ;? 0xf674 0xf000 0x2155 0x46c 0x6a
            for(int i=0;i<strlen(overwrite);i++)
                copy_buffer[0x142B+i*2] = overwrite[i];
            copy_buffer[0x142B+(strlen(overwrite))*2] = '@';
            /* OVERWRITE THE INPUT DATA */
            printf("Trying '%c' '%c'..\n", c1, c2);
            unsigned long exec = vmCode((short*)(((int)base_address)+0x223), 0x2DAD, 5);
            printf("[");
            for(int i=0;i<0xFFFF;i++) {
                if(taintArray[i] >= 1)
                    printf("0x%04X, ", i);
            }
            printf("]\n");
            free(copy_buffer);
            exit(0);
           // printf("'%02X' %lu Instructions Executed\n", i, exec);
            if(exec > highest) {
                highest = exec;
               // highestChar = i&0xFF;
            }
        }
    }
    puts("===================================================");
    printf("%lu Instructions Executed\n", highest);
    free(buffer);
}