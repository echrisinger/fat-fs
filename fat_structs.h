#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define _FAT_DISK_SIZE 10485760
#define _BLOCK_SIZE 4096
#define _SUPERBLOCK_SIZE 512
#define _DIR_SIZE

union Block {
    struct {
        int32_t fat_entry[64];
        char file_name[1024];
        int64_t creation_time;
        int64_t access_time;
        uint32_t file_size;
        int32_t start_block;
        uint32_t flag;
        short unused;
    } b;
    char pad[_BLOCK_SIZE];
};

struct BlockNode {
    uint32_t data;
    struct BlockNode *next;
};

union SuperBlock {
    struct {
        uint32_t block_sz;
        uint32_t n_blocks; // 10485760 / 4096 = 2560 entries total
        uint32_t root_block;
    } s;
    char pad[_SUPERBLOCK_SIZE]; // ensure it is at least a block in size
};