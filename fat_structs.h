#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define _FAT_DISK_SIZE 10485760
#define _BLOCK_SIZE 4096
#define _SUPERBLOCK_SIZE 512
#define _MAX_DIR_NUM 8
#define _MAX_FILE_NAME_SZ 24
#define _MAGIC_NUM 0x1234abcd

union EmptyBlock {
    struct {
        /* EmptyBlock Structure aligns itself in memory with the first directory entry
         * in an in use block. As the first Directory Entry is a reference to the directory itself,
         * the in_use field will always be set to non-zero if the block is in use.
         */
        short in_use;
        /* A reference to the index of the next free block in the 'linked list' of free blocks. When
         * this empty block is used, free_block in the SuperBlock gets set to the free_block field inside
         * this struct. Upon initialization, each block is set sequentially to the next block in memory. 
         */
        int32_t free_block;
    } info;
    char pad[_BLOCK_SIZE];
};

struct DirectoryEntry {
    short in_use;
    char file_name[_MAX_FILE_NAME_SZ];
    int32_t start_block;
    int32_t file_length; //only for use on files. Irrelevant for directories, as they are only one block.
    long last_access;
    long last_modification;
};

union SuperBlock {
    struct {
        uint32_t magic_num;
        uint32_t root_block;
        uint32_t free_block; // reference to next free block (block itself contains reference to the next free block)
        uint32_t block_size;
        uint32_t n_blocks; // 10485760 / 4096 = 2560 entries total
    } info;
    char pad[_SUPERBLOCK_SIZE]; // ensure it is at least a block in size
};