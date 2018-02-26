#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

struct Superblock {
    uint32_t root_block; // k + 1
};


struct Dir_entry {
    char filename[32];
    int64_t creation_time;
    int64_t access_time;
    uint32_t file_length;
    int32_t start_block;
    uint32_t flag;
    uint32_t unused;
};

struct Fat_block {
    int32_t fatentry[256];
};