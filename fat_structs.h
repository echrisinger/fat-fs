#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define _FAT_DISK_SIZE 10485760
#define _BLOCK_SIZE 4096
#define _SUPERBLOCK_SIZE 512
#define _DIR_SIZE 64
#define _MAX_FILE_NAME_SZ 1024
#define _DEFAULT_ENTRY
union Block {
    struct {
        int32_t fat_entry[_DIR_SIZE];
        char file_name[_MAX_FILE_NAME_SZ];
        int64_t creation_time;
        int64_t access_time;
        int32_t start_block;
        uint32_t flag;
        short in_use;
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