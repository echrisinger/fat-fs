/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall -o fat fat.c `pkg-config fuse --cflags --libs`
  pgrep fat | xargs kill -9; fusermount -uz fat-fs/foo; rm -rf fat-fs/foo; mkdir fat-fs/foo; fat-fs/fat fat-fs/foo -d -f -s
*/

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#define HAVE_SETXATTR TRUE

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include "fat_structs.h"

// absolute path to the disk backing file
static char *disk_path = "/home/evan/fat_disk";
static int disk_fd;
static union SuperBlock sb = {};
struct FatEntry *table;

// ----------------------------------------------------
// Helper methods

#define min(a, b) (((a) < (b)) ? (a) : (b)) 
#define max(a, b) (((a) > (b)) ? (a) : (b)) 

// Return the number of blocks used for the SuperBlock and FAT table
int get_backing_blocks_size() {
	int backing_size = (_FAT_DISK_SIZE / sizeof(union Block) * sizeof(struct FatEntry) + sizeof(union SuperBlock));
	return backing_size % sizeof(union Block) == 0 ? backing_size / sizeof(union Block) : backing_size / sizeof(union Block) + 1;
}

void read_SuperBlock(union SuperBlock *sb) {
	int offset = lseek(disk_fd, 0, SEEK_CUR);
	lseek(disk_fd, 0, SEEK_SET);
	read(disk_fd, sb, sizeof(union SuperBlock));
	lseek(disk_fd, offset, SEEK_SET);
}

int write_SuperBlock(union SuperBlock *sb) {
	lseek(disk_fd, 0, SEEK_SET);
	return write(disk_fd, sb, sizeof(union SuperBlock));
}

void read_FatTable(struct FatEntry *table) {
	int offset = lseek(disk_fd, 0, SEEK_CUR);	
	lseek(disk_fd, sizeof(union SuperBlock), SEEK_SET);
	read(disk_fd, table, sizeof(union Block));
	lseek(disk_fd, offset, SEEK_SET);
}

int write_FatTable(struct FatEntry *table) {
	lseek(disk_fd, sizeof(union SuperBlock), SEEK_SET);
	return write(disk_fd, table, sizeof(union Block));
}

// Set File Descriptor offset to be at the beginning of a block
void set_FD_Block_offset(int block_num)
{
	int offset = sizeof(union Block)*get_backing_blocks_size() + block_num*sizeof(union Block);
	lseek(disk_fd, offset, SEEK_SET);
}

int read_Block(union Block *curr_block, int block_num) {
	int offset = lseek(disk_fd, 0, SEEK_CUR);
	set_FD_Block_offset(block_num);
	int res = read(disk_fd, curr_block, sizeof(union Block));
	lseek(disk_fd, offset, SEEK_SET);
	return res;
}

int write_Block(union Block *curr_block, int block_num) {
	set_FD_Block_offset(block_num);
	return write(disk_fd, curr_block, sizeof(union Block));
}

int read_DirectoryEntry(const char *path, struct DirectoryEntry *dir_ent)
{	
	int ret_val = 0;
		
	union Block curr_block = {};
	read_Block(&curr_block, sb.info.root_block);

	if (!strcmp(path, "/")) {
		memcpy(dir_ent, curr_block.block.dir_ents, sizeof(struct DirectoryEntry));
		return ret_val;
	}
	
	char *token = strtok((char *) path, "/");
	struct DirectoryEntry curr_dir_ent;
pathLoop:
	while (token != NULL) {
		for (int i = 0; i < _MAX_DIR_NUM; i++) {
			curr_dir_ent = curr_block.block.dir_ents[i];
			if (curr_dir_ent.in_use && !strcmp(token, curr_dir_ent.file_name)) {
				read_Block(&curr_block, curr_dir_ent.start_block);
				token = strtok(NULL, "/");
				goto pathLoop;
			}
		}
		ret_val = -ENOENT;
		break;
	}
	memcpy(dir_ent, &curr_dir_ent, sizeof(struct DirectoryEntry));

	return ret_val;
}

int write_DirectoryEntry(const char *path, struct DirectoryEntry *dir_ent) {
	int ret_val = 0;
		
	union Block curr_block = {};
	read_Block(&curr_block, sb.info.root_block);

	if (!strcmp(path, "/")) {
		memcpy(dir_ent, curr_block.block.dir_ents, sizeof(struct DirectoryEntry));
		return ret_val;
	}
	
	char *token = strtok((char *) path, "/");
	struct DirectoryEntry curr_dir_ent;
pathLoop:
	while (token != NULL) {
		for (int i = 0; i < _MAX_DIR_NUM; i++) {
			curr_dir_ent = curr_block.block.dir_ents[i];
			if (curr_dir_ent.in_use && !strcmp(token, curr_dir_ent.file_name)) {
				read_Block(&curr_block, curr_dir_ent.start_block);
				token = strtok(NULL, "/");
				goto pathLoop;
			}
		}
		ret_val = -ENOENT;
		break;
	}

	
	memcpy(dir_ent, &curr_dir_ent, sizeof(struct DirectoryEntry));

	return ret_val;
}

void create_SuperBlock(union SuperBlock *sb) {
	sb->info.magic_num = _MAGIC_NUM;
	sb->info.root_block = 0;
	sb->info.free_block = 1;
	sb->info.block_size = sizeof(union Block);
	
	// Calculate the size of the FAT and the number of actual blocks in the table/disk.
	sb->info.n_blocks = _FAT_DISK_SIZE / sizeof(union Block) - get_backing_blocks_size();
	// Corresponding to the root block
	sb->info.num_free_blocks = sb->info.n_blocks - 1;
}

void create_Root_Block(union Block *root_bl) {
	memset(root_bl, 0, sizeof(union Block));
	
	root_bl->block.start_block = 0;
	strcpy(root_bl->block.file_name, "/");
	
	struct DirectoryEntry root = {};
	root.in_use = 1;
	strcpy(root.file_name, ".");
	root.start_block = 0;
	root.file_length = 0;
	memcpy(&root_bl->block.dir_ents[0], &root, sizeof(struct DirectoryEntry));
	
	struct DirectoryEntry root_parent = {};
	root_parent.in_use = 1;
	strcpy(root_parent.file_name, "..");
	root_parent.start_block = 0;
	root_parent.file_length = 0;
	memcpy(&root_bl->block.dir_ents[1], &root_parent, sizeof(struct DirectoryEntry));
}

void create_Block(union Block *new_block, char *file_name, int parent_block) {

	new_block->block.start_block = sb.info.free_block;
	strcpy(new_block->block.file_name, file_name);

	struct DirectoryEntry self_dir = {};
	strcpy(self_dir.file_name, ".");	
	self_dir.in_use 	 = 1;
	self_dir.start_block = new_block->block.start_block;
	memcpy(&new_block->block.dir_ents[0], &self_dir, sizeof(struct DirectoryEntry));

	struct DirectoryEntry parent_dir = {};
	strcpy(parent_dir.file_name, "..");
	parent_dir.in_use 	   = 1;
	parent_dir.start_block = parent_block;
	memcpy(&new_block->block.dir_ents[1], &parent_dir, sizeof(struct DirectoryEntry));
}

void create_FatTable(struct FatEntry *table) {
	table[0].in_use = 1;
	table[0].next = -1;
	
	struct FatEntry empty_entry = {in_use: 0};
	for (int i = 1; i < sb.info.n_blocks; i++) {
		if (i != sb.info.n_blocks-1) {
			empty_entry.next = i+1;
		} else {
			empty_entry.next = -1;
		}
		memcpy(&table[i], &empty_entry, sizeof(struct FatEntry));
	}
}

int split_subpath_filename(char *path, char *subpath, char *file_name) {
	char *tokens[100];
	tokens[0] = strtok((char *) path, "/");
	int i = 0;
	while(tokens[i] != NULL) {
		i++;
		tokens[i] = strtok(NULL, "/");
	}

	strcpy(subpath, "");
	for (int j = 0; j < i-1; j++) {
		strcat(subpath, "/");
		strcat(subpath, tokens[j]);
	}

	strcpy(file_name, tokens[i-1]);
	for (int x = 0; x < i; x++) {
		free(tokens[i]);
	}
	
	return i;
}

int get_path_block(char *subpath, union Block *block) {
	if (sb.info.free_block >= sb.info.n_blocks) {
		return -ENOSPC;
	}

	struct DirectoryEntry dir_ent = {};
	if (strlen(subpath) > 0 && read_DirectoryEntry(subpath, &dir_ent) == -ENOENT) {
		return -ENOENT;
	}

	read_Block(block, dir_ent.start_block);
	return dir_ent.start_block;
}

void fill_stat(struct stat *stbuf, struct DirectoryEntry dir_ent) {
	struct fuse_context *context = fuse_get_context();
	struct FatEntry table_entry = table[dir_ent.start_block];

	if (table_entry.in_use == 1) {
		stbuf->st_mode   = S_IFDIR | 0666;
	} else {
		stbuf->st_mode	 = S_IFREG | 0666;
	}
	stbuf->st_atime  = time(0);
	stbuf->st_mtime  = time(0);
	stbuf->st_ino    = dir_ent.start_block;
	stbuf->st_nlink  = 1;
	stbuf->st_uid	 = (int) context->uid;
	stbuf->st_gid	 = (int) context->gid;
	stbuf->st_blocks = sizeof(union Block) / 512;
	stbuf->st_size   = dir_ent.file_length;
}

// ---------------------------------------------------

static void *fat_init(struct fuse_conn_info *conn) 
{

	if (access(disk_path, F_OK) == -1) {
		// Zero out the entire disk and reset position.
		disk_fd = open(disk_path, (O_RDWR | O_CREAT), 0777);
		char* FULL_DISK = (char *) malloc(_FAT_DISK_SIZE);
		memset(FULL_DISK, 0, _FAT_DISK_SIZE);
		write(disk_fd, &FULL_DISK, _FAT_DISK_SIZE);
		lseek(disk_fd, 0, SEEK_SET);

		// Create the Superblock and write it.
		create_SuperBlock(&sb);
		int sb_sz = write_SuperBlock(&sb);
		
		// Check for errors
		if (sb_sz < 0) {
			char *err_msg = "Error creating the super block\n";
			write(2, err_msg, strlen(err_msg));
			close(disk_fd);
			exit(0);
		} else if (sb_sz != sizeof(sb)) {
			char *err_msg = "Super block not written to proper size.\n";
			write(2, err_msg, strlen(err_msg));
			close(disk_fd);			
			exit(0);			
		}
		
		// Create the root block and write it.
		union Block root_bl = {};
		memset(&root_bl, 0, sizeof(root_bl));
		create_Root_Block(&root_bl);
		
		// Check for errors while writing
		if (write_Block(&root_bl, 0) != sizeof(union Block)) {
			char *err_msg = "Root dir not written to proper size.\n";
			write(2, err_msg, strlen(err_msg));
			close(disk_fd);
			exit(0);
		}
		
		// Populate the table entries and write them
		table = malloc(sizeof(struct FatEntry)*sb.info.n_blocks);
		create_FatTable(table);
		write_FatTable(table);
		
		free(FULL_DISK);
	} else {
		read_SuperBlock(&sb);
		read_FatTable(table);
	}
	return NULL;
}

static int fat_access(const char *path, int mask)
{
	struct DirectoryEntry dir_ent = {};
	int res = read_DirectoryEntry(path, &dir_ent);
	return res;
}


static int fat_getattr(const char *path, struct stat *stbuf)
{
	memset(stbuf, 0, sizeof(struct stat));
	struct DirectoryEntry dir_ent = {};
	int res = read_DirectoryEntry(path, &dir_ent);
	if (res == -ENOENT) {
		return res;
	}
	fill_stat(stbuf, dir_ent);
	if (strcmp(path, "/")) {
		stbuf->st_nlink = 2;
	}
	return res;
}


static int fat_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	struct DirectoryEntry parent_dir_ent = {};
	int res = read_DirectoryEntry(path, &parent_dir_ent);

	union Block dir_block = {};
	if(!strcmp(path, "/")) {
		read_Block(&dir_block, sb.info.root_block);
	} else {
		if(res == -ENOENT) {
			return res;
		}
		read_Block(&dir_block, parent_dir_ent.start_block);
	}
	
	struct DirectoryEntry dir_ent = {};
	for (int i = offset; i < _MAX_DIR_NUM; i++) {
		dir_ent = dir_block.block.dir_ents[i];
		if (dir_ent.in_use) {
			struct stat st = {};
			fill_stat(&st, dir_ent);
			if(filler(buf, dir_ent.file_name, &st, i+1)) {
				return 0;
			}
		}
	}

	return 0;
}

static int fat_mkdir(const char *path, mode_t mode)
{
	char *subpath = malloc(4096);
	char *file_name = malloc(4096);
	int path_tokens_sz = split_subpath_filename((char *) path, subpath, file_name);

	if (strlen(file_name) >= _MAX_FILE_NAME_SZ) {
		return -ENAMETOOLONG;
	}


	union Block parent_block = {};
	int res = get_path_block((char *) subpath, &parent_block);

	
	if (path_tokens_sz == 1) {
		read_Block(&parent_block, sb.info.root_block);
	} else if (res < 0) {
		return res;
	}

	
	for (int i = 0; i < _MAX_DIR_NUM; i++) {
		struct DirectoryEntry parent_dir_ent = parent_block.block.dir_ents[i];
		if (!parent_dir_ent.in_use) {
			parent_dir_ent.in_use = 1;
			parent_dir_ent.start_block = sb.info.free_block;
			strcpy(parent_dir_ent.file_name, file_name);
			memcpy(&parent_block.block.dir_ents[i], &parent_dir_ent, sizeof(struct DirectoryEntry));
			break;
		}
		if (i == _MAX_DIR_NUM - 1) {
			return -ENOSPC;
		}
	}

	write_Block(&parent_block, res);

	// Create the new block after the parent block.
	union Block new_block = {};
	create_Block(&new_block, file_name, sb.info.free_block);
	write_Block(&new_block, new_block.block.start_block);

	// Update the FAT table for the newly added block, modify the SuperBlock to point to next free block
	// Write the newly updated SuperBlock
	struct FatEntry *entry = &table[new_block.block.start_block];
	sb.info.free_block = entry->next;
	entry->next   = -1;
	entry->in_use = 1;
	write_FatTable(table);
	write_SuperBlock(&sb);

	free(subpath);
	free(file_name);
	return 0;
}

// Works
static int fat_mknod(const char* path, mode_t mode, dev_t rdev) {
	// If it doesn't have S_IFREG perms.
	if(~((mode & S_IFREG) ^ ~S_IFREG)) {
		return -EACCES;
	}

	char *subpath = malloc(4096);
	char *file_name = malloc(4096);
	int path_tokens_sz = split_subpath_filename((char *) path, subpath, file_name);

	if (strlen(file_name) >= _MAX_FILE_NAME_SZ) {
		return -ENAMETOOLONG;
	}


	union Block parent_block = {};
	int res = get_path_block((char *) subpath, &parent_block);

	
	if (path_tokens_sz == 1) {
		read_Block(&parent_block, sb.info.root_block);
	} else if (res < 0) {
		return res;
	}

	
	for (int i = 0; i < _MAX_DIR_NUM; i++) {
		struct DirectoryEntry parent_dir_ent = parent_block.block.dir_ents[i];
		if (!parent_dir_ent.in_use) {
			parent_dir_ent.in_use = 2;
			parent_dir_ent.start_block = sb.info.free_block;
			parent_dir_ent.file_length = 0;
			strcpy(parent_dir_ent.file_name, file_name);
			memcpy(&parent_block.block.dir_ents[i], &parent_dir_ent, sizeof(struct DirectoryEntry));
			break;
		}
		if (i == _MAX_DIR_NUM - 1) {
			return -ENOSPC;
		}
	}

	write_Block(&parent_block, res);

	struct FatEntry *temp = &table[sb.info.free_block];
	
	// Write the newly updated SuperBlock
	sb.info.free_block = temp->next;
	temp->next   = -1;
	temp->in_use = 2;
	write_FatTable(table);
	write_SuperBlock(&sb);


	free(subpath);
	free(file_name);
	return 0;
}

static int fat_open(const char* path, struct fuse_file_info* fi) {
	struct DirectoryEntry dir_ent = {};
	int res = read_DirectoryEntry(path, &dir_ent);
	return res;
}

static int fat_read(const char* path, char *buf, size_t size, off_t offset, struct fuse_file_info* fi) {
	struct DirectoryEntry dir_ent = {};
	int res = read_DirectoryEntry(path, &dir_ent);
	if (res < 0) {
		return res;
	} else if (size+offset > dir_ent.file_length) {
		size = dir_ent.file_length - offset;
	}

	struct FatEntry *prev = &table[dir_ent.start_block];
	struct FatEntry *next = &table[dir_ent.start_block];
	int block_num = dir_ent.start_block;
	while (offset > _BLOCK_SIZE) {
		if (table[prev->next].next == -1) {
			return 0;
		}
		offset -= _BLOCK_SIZE;
		prev = next;
		next = &table[next->next];
		block_num = prev->next;
	}

	char *buf_ptr = buf;
	int blk_read_sz = min(size, _BLOCK_SIZE-offset);
	
	union Block curr_block = {};
	read_Block(&curr_block, block_num);
	memcpy(buf_ptr, &curr_block+offset, blk_read_sz);
	
	buf_ptr += blk_read_sz;
	int read_acc = blk_read_sz;

	while(read_acc < size) {
		if (table[prev->next].next == -1) {
			return read_acc;
		}
		prev = next;
		next = &table[next->next];
		read_Block(&curr_block, prev->next);
		blk_read_sz = min(_BLOCK_SIZE, size-read_acc);
		memcpy(buf_ptr, &curr_block, blk_read_sz);
		buf_ptr += blk_read_sz;
		read_acc += blk_read_sz;
	}

	return read_acc;
}

// Works
static int fat_write(const char* path, const char *buf, size_t size, off_t offset, struct fuse_file_info* fi) {
	struct DirectoryEntry dir_ent = {};
	int res = read_DirectoryEntry(path, &dir_ent);
	if (res < 0) {
		return res;
	}
	
	union Block parent_block = {};
	read_Block(&parent_block, res);
	for (int i = 0; i < _MAX_DIR_NUM; i++) {
		if(!strcmp(parent_block.block.dir_ents[i].file_name, dir_ent.file_name)) {
			parent_block.block.dir_ents[i].file_length = max(offset+size, parent_block.block.dir_ents[i].file_length);
		}
	}
	write_Block(&parent_block, res);

	struct FatEntry *prev = &table[dir_ent.start_block];
	struct FatEntry *next = prev;
	int block_num = dir_ent.start_block;
	while (offset > sizeof(union Block)) {
		if (next->next >= 0) {
			prev = next;
			next = &table[next->next];
		} else {
			// Change next block to be new block.
			if (sb.info.free_block >= sb.info.n_blocks) {
				return -ENOSPC;
			}
			// TODO: figure out if this works
			next->next = sb.info.free_block;

			// Read in the next block.
			struct FatEntry *temp = &table[sb.info.free_block];
			printf("in else\n");
			// Modify the SuperBlock's free_block head.
			sb.info.free_block = temp->next;
			temp->in_use = 2;
			temp->next = -1;
			
			prev = next;
			next = temp;
			write_FatTable(table);
			write_SuperBlock(&sb);
		}
		offset -= _BLOCK_SIZE;
		block_num = prev->next;
	}
	
	// Move to write position in first block to be written to.
	char *buf_ptr = (char *) buf;
	int block_write_sz = min(_BLOCK_SIZE-offset, size);
	char *curr_block = malloc(sizeof(union Block));
	read_Block((union Block *) curr_block, block_num);
	memcpy(curr_block+offset, buf_ptr, block_write_sz);
	write_Block((union Block *) curr_block, block_num);
	
	int write_acc = block_write_sz;
	buf_ptr += block_write_sz;

	while (write_acc < size) {
		
		if (next->next >= 0) {
			prev = next;
			next = &table[next->next];
		} else {
			if (sb.info.free_block >= sb.info.n_blocks) {
				return -ENOSPC;
			}
			next->next = sb.info.free_block;
			struct FatEntry *temp = &table[next->next];
			
			sb.info.free_block = temp->next;			
			temp->in_use = 2;
			temp->next = -1;
			prev = next;
			next = temp;
			write_FatTable(table);
			write_SuperBlock(&sb);
		}
		block_write_sz = min(_BLOCK_SIZE, size-write_acc);
		read_Block((union Block *) curr_block, prev->next);
		memcpy(curr_block, buf_ptr, block_write_sz);
		write_Block((union Block *) curr_block, prev->next);
		write_acc += block_write_sz;
		buf_ptr += block_write_sz;
	}
	free(curr_block);
	
	return write_acc;
}

// Presumably works
static int fat_release(const char* path, struct fuse_file_info *fi) {
	struct DirectoryEntry dir_ent = {};
	int res = read_DirectoryEntry(path, &dir_ent);
	if (res < 0) {
		printf("error in release\n");
		return res;
	}
	return 0;
}

// Functional
static int fat_create(const char* path, mode_t mode) {
	int res = fat_mknod(path, mode | S_IFREG, 0);
	return res;
}

// Functional
static int fat_truncate(const char* path, off_t size) {
	char *subpath = malloc(4096);
	char *file_name = malloc(4096);
	split_subpath_filename((char *) path, subpath, file_name);

	union Block parent_block = {};
	int res = get_path_block((char *) subpath, &parent_block);
	
	if (res < 0) {
		return res;
	}

	
	struct DirectoryEntry parent_dir_ent = {};
	int i;
	for (i = 0; i < _MAX_DIR_NUM; i++) {
		parent_dir_ent = parent_block.block.dir_ents[i];
		if (parent_dir_ent.in_use && !strcmp(parent_dir_ent.file_name, file_name)) {
			break;
		} else if (i == _MAX_DIR_NUM-1) {
			return -ENOENT;
		}
	}

	int orig_size = parent_block.block.dir_ents[i].file_length;
	parent_block.block.dir_ents[i].file_length = size;
	write_Block(&parent_block, res);

	if (orig_size <= size) {
		int n_zeros = size - parent_block.block.dir_ents[i].file_length;
		char * zeros = malloc(n_zeros);		
		memset(zeros, 0, n_zeros);
		int res = fat_write(path, zeros, n_zeros, orig_size, NULL);
		if (res < 0) {
			return res;
		}
		return 0;
	}

	
	struct FatEntry *prev = &table[parent_block.block.start_block];
	struct FatEntry *next = prev;
	
	
	while (size > sizeof(union Block)) {
		size -= sizeof(union Block);
		prev = next;
		next = &table[next->next];
	}
	
	
	int last = prev->next;
	int first_free = next->next;

	int curr = next->next;
	while(table[curr].next != -1) {
		table[curr].in_use = 0;
		curr = table[curr].next;
	}

	
	table[curr].next = sb.info.free_block;
	sb.info.free_block = first_free;

	// 0 out the remaining memory of the block for cleanliness.
	// Write the block
	char *blk_memory = malloc(sizeof(union Block));
	read_Block((union Block *) blk_memory, last);
	memset(blk_memory+size, 0, sizeof(union Block)-size);
	write_Block((union Block *) blk_memory, last);
	write_FatTable(table);
	// Write the superblock
	write_SuperBlock(&sb);
	return 0;
}

// Works
static int fat_rmdir(const char* path) {
	char *subpath = malloc(4096);
	char *file_name = malloc(4096);
	split_subpath_filename((char *) path, subpath, file_name);

	union Block parent_block = {};
	int res = get_path_block((char *) subpath, &parent_block);
	
	if (res < 0) {
		return res;
	}

	struct DirectoryEntry parent_dir_ent = {};
	int i;
	for (i = 0; i < _MAX_DIR_NUM; i++) {
		parent_dir_ent = parent_block.block.dir_ents[i];
		if (parent_dir_ent.in_use && !strcmp(parent_dir_ent.file_name, file_name)) {
			break;
		} else if (i == _MAX_DIR_NUM-1) {
			return -ENOENT;
		}
	}

	union Block dir_block = {};
	read_Block(&dir_block, parent_dir_ent.start_block);
	int count = 0;
	for (int j = 0; j < _MAX_DIR_NUM; j++) {
		if (dir_block.block.dir_ents[j].in_use) {
			count++;
		}
	}

	if (count > 2) {
		return -1;
	}

	struct FatEntry *entry = &table[parent_dir_ent.start_block];
	entry->next = sb.info.free_block;
	entry->in_use = 0;
	sb.info.free_block = parent_dir_ent.start_block;
	write_FatTable(table);
	write_SuperBlock(&sb);

	// 0 the block
	memset(&dir_block, 0, sizeof(union Block));
	write_Block(&dir_block, parent_dir_ent.start_block);

	// 0 the entry in the parent directory entry
	memset(&parent_block.block.dir_ents[i], 0, sizeof(struct DirectoryEntry));
	write_Block(&parent_block, parent_block.block.dir_ents[0].start_block);	
	
	return 0;
}

static int fat_symlink(const char* to, const char* from) {
	char *subpath_to = malloc(4096);
	char *file_name_to = malloc(4096);
	split_subpath_filename((char *) to, subpath_to, file_name_to);

	union Block parent_block_to = {};
	int res = get_path_block((char *) subpath_to, &parent_block_to);
	
	if (res < 0) {
		return res;
	}

	struct DirectoryEntry parent_dir_ent_to = {};
	int i;
	for (i = 0; i < _MAX_DIR_NUM; i++) {
		parent_dir_ent_to = parent_block_to.block.dir_ents[i];
		if (parent_dir_ent_to.in_use && !strcmp(parent_dir_ent_to.file_name, file_name_to)) {
			break;
		} else if (i == _MAX_DIR_NUM-1) {
			return -ENOENT;
		}
	}

	char *subpath_from = malloc(4096);
	char *file_name_from = malloc(4096);
	split_subpath_filename((char *) from, subpath_from, file_name_from);

	union Block parent_block_from = {};
	int res2 = get_path_block((char *) subpath_from, &parent_block_from);
	
	if (res2 < 0) {
		return res2;
	}

	struct DirectoryEntry parent_dir_ent_from = {};
	int j;
	for (j = 0; j < _MAX_DIR_NUM; j++) {
		parent_dir_ent_from = parent_block_from.block.dir_ents[j];
		if (!parent_dir_ent_from.in_use) {
			strcpy(parent_block_from.block.dir_ents[j].file_name, file_name_from);
			parent_block_from.block.dir_ents[j].in_use = 1;
			parent_block_from.block.dir_ents[j].start_block = parent_dir_ent_to.start_block;
			parent_block_from.block.dir_ents[j].file_length = parent_dir_ent_to.file_length;
			break;
		} else if (j == _MAX_DIR_NUM-1) {
			return -ENOENT;
		}
	}

	write_Block(&parent_block_from, res2);
	return 0;
}

// TODO: fgetattr, readlink, unlink, symlink
// Correct number of hard links
// Correct number of remaining files
// Fix symlink behavior

// DONE: close (i.e., release), create, mknod (only for plain files), 
// open, read, and write, truncate, rmdir, statfs,


static int fat_statfs(const char* path, struct statvfs* stbuf) {
	stbuf->f_bsize  = sizeof(union Block);
	stbuf->f_frsize = sizeof(union Block);
	stbuf->f_fsid 	= sb.info.magic_num;
	stbuf->f_namemax = _MAX_FILE_NAME_SZ;
	stbuf->f_blocks = sb.info.n_blocks;
	stbuf->f_files  = sb.info.n_blocks;
	stbuf->f_flag   = 0666;
	stbuf->f_bfree  = sb.info.n_blocks;
	stbuf->f_bavail = sb.info.n_blocks;
	stbuf->f_ffree  = sb.info.n_blocks;
	stbuf->f_favail = sb.info.n_blocks;
	return 0;
}

// Some of these are only implemented because of errors in debug console w/o them
static int fat_utimens(const char* path, const struct timespec ts[2]) {
	return 0;
}

static int fat_chmod(const char* path, mode_t mode) {
	return 0;
}

static int fat_chown(const char* path, uid_t uid, gid_t gid) {
	return 0;
}

static int fat_flush(const char* path, struct fuse_file_info* fi) {
	return 0;
}

static int fat_getxattr(const char* path, const char* name, char* value, size_t size) {
	return 0;
}


static struct fuse_operations fat_oper = {
	.init       = fat_init,
	.access		= fat_access,
	.getattr	= fat_getattr,
	.readdir	= fat_readdir,
	.mkdir		= fat_mkdir,
	.mknod		= fat_mknod,
	.open		= fat_open,
	.read		= fat_read,
	.write		= fat_write,
	.create		= fat_create,
	.release	= fat_release,
	.truncate	= fat_truncate,
	.rmdir		= fat_rmdir,
	.symlink	= fat_symlink,
	.statfs		= fat_statfs,
	.chmod		= fat_chmod,
	.chown		= fat_chown,
	.utimens	= fat_utimens,
	.flush		= fat_flush,
#ifdef HAVE_SETXATTR
	.getxattr	= fat_getxattr,
#endif
	.flag_nullpath_ok = 0
};

int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &fat_oper, NULL);
}