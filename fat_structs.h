#define _FAT_DISK_SIZE 10485760
#define _BLOCK_SIZE 4096
#define _SUPERBLOCK_SIZE 512
#define _MAX_DIR_NUM 8
#define _MAX_FILE_NAME_SZ 24
#define _MAGIC_NUM 0x1234abcd

/*
 * Fat Table Structure:
 * superblock (512) 
 * in-core table + pad (remaining of first 3 blocks)
 * root directory (block 3)
 * ... the rest
 */
struct FatEntry {
    short in_use;
    short next;
};

struct DirectoryEntry {
    short in_use;
    char file_name[_MAX_FILE_NAME_SZ];
    int32_t start_block;
    int32_t file_length; //only for use on files. Irrelevant for directories, as they are only one block.
};

union Block {
    struct {
        int32_t start_block;
        int32_t file_length;
        char file_name[_MAX_FILE_NAME_SZ];
        struct DirectoryEntry dir_ents[_MAX_DIR_NUM];
    } block;
    char pad[_BLOCK_SIZE];
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