#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <stdint.h>
#include <sys/msg.h>

// gcc everlasting_message_preload.c -o everlasting_message_preload.so -fPIC -shared -ldl -D_GNU_SOURCE
// LD_PRELOAD=$PWD/everlasting_message_preload.so ./messages msg.txt msg.bin

int msgget(key_t key, int msgflg) {
    
    Dl_info dlinfo;
    dladdr(__builtin_return_address(0), &dlinfo);
    
    unsigned char * base_addr = (unsigned char*) dlinfo.dli_fbase;

    uint64_t (*enc0)(uint64_t) = (void*)(base_addr + 0x12e9); // enc0
    uint64_t (*enc1)(uint64_t) = (void*)(base_addr + 0x264d); // enc1
    uint64_t (*enc2)(uint64_t) = (void*)(base_addr + 0x3977); // enc2
    uint64_t (*enc3)(uint64_t) = (void*)(base_addr + 0x4c0e); // enc3
    
    for(uint64_t i=0;i<=0xfffff;i++) {
        // run this for each encryption function once
        printf("%05lX %010lX\n", i, enc0(i));
    }

    exit(0);
    return 0;
}