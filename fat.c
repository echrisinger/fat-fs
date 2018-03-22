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
// ----------------------------------------------------
// Helper methods

#define min(a, b) (((a) < (b)) ? (a) : (b)) 
#define max(a, b) (((a) > (b)) ? (a) : (b)) 

// Return the number of blocks used for the SuperBlock and FAT table
int get_backing_blocks_size() {
	int backing_size = (_FAT_DISK_SIZE / _BLOCK_SIZE * sizeof(struct FatEntry) + _SUPERBLOCK_SIZE);
	return backing_size % _BLOCK_SIZE == 0 ? backing_size / _BLOCK_SIZE : backing_size / _BLOCK_SIZE + 1;
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

// Set File Descriptor offset to be at the beginning of a block
void set_FD_Block_offset(int block_num)
{
	union SuperBlock sb = {};
	read_SuperBlock(&sb); 
	int offset = _BLOCK_SIZE*get_backing_blocks_size() + block_num*_BLOCK_SIZE;
	lseek(disk_fd, offset, SEEK_SET);
}

int read_Block(union Block *curr_block, int block_num) {
	set_FD_Block_offset(block_num);
	return read(disk_fd, curr_block, sizeof(union Block));
}

int write_Block(union Block *curr_block, int block_num) {
	set_FD_Block_offset(block_num);
	return write(disk_fd, curr_block, sizeof(union Block));
}

int read_DirectoryEntry(const char *path, struct DirectoryEntry *dir_ent)
{	
	int ret_val = 0;
	
	union SuperBlock sb = {}; 
	read_SuperBlock(&sb);
	
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
	
	union SuperBlock sb = {}; 
	read_SuperBlock(&sb);
	
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

/* Write the FatEntry to it's position in the FAT, and then reset the
 * fd's position to where it was originally.
 */
void write_TableEntry(int block_num, struct FatEntry *entry) {
	int orig_pos = lseek(disk_fd, 0, SEEK_CUR);
	int offset   = sizeof(union SuperBlock) + block_num*sizeof(struct FatEntry);
	lseek(disk_fd, offset, SEEK_SET);
	write(disk_fd, entry, sizeof(struct FatEntry));
	lseek(disk_fd, orig_pos, SEEK_SET);
}

void read_TableEntry(int block_num, struct FatEntry *entry) {
	int orig_pos = lseek(disk_fd, 0, SEEK_CUR);
	int offset   = sizeof(union SuperBlock) + block_num*sizeof(struct FatEntry);
	lseek(disk_fd, offset, SEEK_SET);
	read(disk_fd, entry, sizeof(struct FatEntry));
	lseek(disk_fd, orig_pos, SEEK_SET);	
}

void create_SuperBlock(union SuperBlock *sb) {
	sb->info.magic_num = _MAGIC_NUM;
	sb->info.root_block = 0;
	sb->info.free_block = 1;
	sb->info.block_size = _BLOCK_SIZE;

	// Calculate the size of the FAT and the number of actual blocks in the table/disk.
	sb->info.n_blocks = _FAT_DISK_SIZE / _BLOCK_SIZE - get_backing_blocks_size();
}
void create_root_Block(union Block *root_bl) {
	memset(root_bl, 0, _BLOCK_SIZE);
	
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
	union SuperBlock sb = {};
	read_SuperBlock(&sb);
	
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

void create_FAT_table(struct FatEntry *table, union SuperBlock sb) {
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
	
	union SuperBlock sb = {};
	read_SuperBlock(&sb);

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
	struct FatEntry table_entry = {};
	read_TableEntry(dir_ent.start_block, &table_entry);
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
	stbuf->st_blocks = _BLOCK_SIZE / 512;
	stbuf->st_size   = _BLOCK_SIZE;
}

// ---------------------------------------------------

static void *fat_init(struct fuse_conn_info *conn) 
{

	if (access(disk_path, F_OK) == -1) {
		// Zero out the entire disk and reset position.
		disk_fd = open(disk_path, (O_RDWR | O_CREAT), 0666);
		char* FULL_DISK = (char *) malloc(_FAT_DISK_SIZE);
		memset(FULL_DISK, 0, _FAT_DISK_SIZE);
		write(disk_fd, &FULL_DISK, _FAT_DISK_SIZE);
		lseek(disk_fd, 0, SEEK_SET);

		// Create the Superblock and write it.
		union SuperBlock sb = {};
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
		create_root_Block(&root_bl);
		
		// Check for errors while writing
		if (write_Block(&root_bl, 0) != _BLOCK_SIZE) {
			char *err_msg = "Root dir not written to proper size.\n";
			write(2, err_msg, strlen(err_msg));
			close(disk_fd);
			exit(0);
		}
		
		// Populate the table entries and write them
		struct FatEntry *table = malloc(sizeof(struct  FatEntry)*sb.info.n_blocks);
		create_FAT_table(table, sb);
		
		lseek(disk_fd, _SUPERBLOCK_SIZE, SEEK_SET);
		write(disk_fd, table, sizeof(struct FatEntry)*sb.info.n_blocks);
		
		free(FULL_DISK);
		free(table);
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

	union SuperBlock sb = {};
	read_SuperBlock(&sb);

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
	union SuperBlock sb = {};
	read_SuperBlock(&sb);
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
	struct FatEntry block_entry = {};
	read_TableEntry(new_block.block.start_block, &block_entry);
	sb.info.free_block = block_entry.next;
	block_entry.next   = -1;
	block_entry.in_use = 1;
	write_TableEntry(new_block.block.start_block, &block_entry);

	// Write the newly updated SuperBlock
	write_SuperBlock(&sb);

	free(subpath);
	free(file_name);
	return 0;
}

// Workds
static int fat_mknod(const char* path, mode_t mode, dev_t rdev) {
	// If it doesn't have S_IFREG perms.
	if (~((mode & S_IFREG) ^ ~S_IFREG)) {
		return -EACCES;
	}

	char *subpath = malloc(4096);
	char *file_name = malloc(4096);
	int path_tokens_sz = split_subpath_filename((char *) path, subpath, file_name);

	if (strlen(file_name) >= _MAX_FILE_NAME_SZ) {
		return -ENAMETOOLONG;
	}


	union Block parent_block = {};
	union SuperBlock sb = {};
	read_SuperBlock(&sb);
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

	int temp = sb.info.free_block;
	
	struct FatEntry block_entry = {};
	read_TableEntry(sb.info.free_block, &block_entry);
	sb.info.free_block = block_entry.next;
	block_entry.next   = -1;
	block_entry.in_use = 2;
	write_TableEntry(temp, &block_entry);

	// Write the newly updated SuperBlock
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
	}

	set_FD_Block_offset(dir_ent.start_block);
	lseek(disk_fd, offset, SEEK_CUR);
	res = read(disk_fd, buf, max(0, min(dir_ent.file_length-offset, size)));
	return res;
}

// Works
static int fat_write(const char* path, const char *buf, size_t size, off_t offset, struct fuse_file_info* fi) {
	struct DirectoryEntry dir_ent = {};
	int res = read_DirectoryEntry(path, &dir_ent);
	if (res < 0) {
		return res;
	}

	struct FatEntry prev = {};
	struct FatEntry next = {};
	read_TableEntry(dir_ent.start_block, &next);
	memcpy(&prev, &next, sizeof(struct FatEntry));
	
	union SuperBlock sb = {};
	read_SuperBlock(&sb);

	int block_num = dir_ent.start_block;
	while (offset > _BLOCK_SIZE) {
		if (next.next >= 0) {
			prev = next;
			read_TableEntry(next.next, &next);
		} else {
			// Change next block to be new block.
			if (sb.info.free_block >= sb.info.n_blocks) {
				return -ENOSPC;
			}
			next.next = sb.info.free_block;
			write_TableEntry(prev.next, &next);

			// Read in the next block.
			struct FatEntry temp = {};
			read_TableEntry(sb.info.free_block, &temp);

			// Modify the SuperBlock's free_block head.
			sb.info.free_block = temp.next;
			temp.in_use = 2;
			temp.next = -1;

			prev = next;
			next = temp;
			
			// Write the new block's changed state to disk
			write_TableEntry(prev.next, &next);
		}
		offset -= offset;
		block_num = prev.next;
	}

	// Write the SuperBlock after potential changes have been made.
	write_SuperBlock(&sb);
	
	// Move to write position in first block to be written to.
	set_FD_Block_offset(block_num);
	lseek(disk_fd, offset, SEEK_CUR);
	int some_write_sz = min(_BLOCK_SIZE-offset, size);
	write(disk_fd, buf, some_write_sz);
	size -= some_write_sz;
	buf += some_write_sz;

	while (size > 0) {
		if (next.next >= 0) {
			prev = next;
			read_TableEntry(next.next, &next);
		} else {
			if (sb.info.free_block >= sb.info.n_blocks) {
				return -ENOSPC;
			}
			next.next = sb.info.free_block;
			write_TableEntry(prev.next, &next);
			struct FatEntry temp = {};
			read_TableEntry(next.next, &temp);
			sb.info.free_block = temp.next;			
			temp.in_use = 2;
			temp.next = -1;
			prev = next;
			next = temp;
			write_TableEntry(prev.next, &next);
		}

		set_FD_Block_offset(prev.next);
		some_write_sz = min(_BLOCK_SIZE, size);
		write(disk_fd, buf, some_write_sz);
		size -= some_write_sz;
		buf += some_write_sz;
	}

	write_SuperBlock(&sb);

	return 0;
}

// Presumably works
static int fat_release(const char* path, struct fuse_file_info *fi) {
	struct DirectoryEntry dir_ent = {};
	int res = read_DirectoryEntry(path, &dir_ent);
	if (res < 0) {
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

	if (parent_block.block.dir_ents[i].file_length <= size) {
		return 0;	
	}

	parent_block.block.dir_ents[i].file_length = size;
	write_Block(&parent_block, res);
	
	union SuperBlock sb = {};
	read_SuperBlock(&sb);

	struct FatEntry table[sb.info.n_blocks];
	lseek(disk_fd, sizeof(union SuperBlock), SEEK_SET);
	read(disk_fd, &table, sizeof(struct FatEntry)*sb.info.n_blocks);
	struct FatEntry prev = table[parent_block.block.start_block];
	struct FatEntry next = table[parent_block.block.start_block];
	
	while (size > _BLOCK_SIZE) {
		size -= _BLOCK_SIZE;
		prev = next;
		next = table[next.next];
	}
	
	int last = prev.next;
	int first_free = next.next;

	int curr = next.next;
	while(table[curr].next != -1) {
		table[curr].in_use = 0;
		curr = table[curr].next;
	}
	table[curr].next = sb.info.free_block;
	sb.info.free_block = first_free;

	// 0 out the remaining memory of the block for cleanliness.
	// Write the block
	char *blk_memory = malloc(_BLOCK_SIZE);
	read_Block((union Block *) &blk_memory, last);
	memset(blk_memory+size, 0, _BLOCK_SIZE-size);
	write_Block((union Block *) blk_memory, last);
	
	// Write the table
	lseek(disk_fd, _SUPERBLOCK_SIZE, SEEK_SET);
	write(disk_fd, table, sizeof(struct FatEntry)*sb.info.n_blocks);

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

	union SuperBlock sb = {};
	read_SuperBlock(&sb);

	struct FatEntry entry = {};
	read_TableEntry(parent_dir_ent.start_block, &entry);
	entry.next = sb.info.free_block;
	entry.in_use = 0;
	write_TableEntry(parent_dir_ent.start_block, &entry);

	sb.info.free_block = parent_dir_ent.start_block;
	write_SuperBlock(&sb);

	memset(&dir_block, 0, _BLOCK_SIZE);
	write_Block(&dir_block, parent_dir_ent.start_block);

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

// TODO: fgetattr, readlink, unlink, symlink,
// Correct number of hard links
// Correct number of remaining files
// Fix symlink behavior
// Fix permissions
// File types

// DONE: close (i.e., release), create, mknod (only for plain files), 
// open, read, and write, truncate, rmdir, statfs,


static int fat_statfs(const char* path, struct statvfs* stbuf) {
	union SuperBlock sb = {};
	read_SuperBlock(&sb);
	stbuf->f_bsize  = _BLOCK_SIZE;
	stbuf->f_frsize = _BLOCK_SIZE;
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

static int fat_utimens(const char* path, const struct timespec ts[2]) {
	return 0;
}

static int fat_chmod(const char* path, mode_t mode) {
	return 0;
}

static int fat_chown(const char* path, uid_t uid, gid_t gid) {
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
};

int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &fat_oper, NULL);
}