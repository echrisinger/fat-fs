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

/*
 * TODOs:
 * Correct number of hard links
 */

// absolute path to the disk backing file
static char *disk_path = "/home/evan/fat_disk";

// ----------------------------------------------------
// Helper methods

// Return the number of blocks used for the SuperBlock and FAT table
int get_backing_blocks_size() {
	int backing_size = (_FAT_DISK_SIZE / _BLOCK_SIZE * sizeof(struct FatEntry) + _SUPERBLOCK_SIZE);
	return backing_size % _BLOCK_SIZE == 0 ? backing_size / _BLOCK_SIZE : backing_size / _BLOCK_SIZE + 1;
}

// Set File Descriptor offset to be at the beginning of a block
void set_block_offset(int block_num, int disk_fd, union SuperBlock sb)
{
	int offset = _BLOCK_SIZE*get_backing_blocks_size() + block_num*_BLOCK_SIZE;
	lseek(disk_fd, offset, SEEK_SET);
}

int find_dir(const char *path, struct DirectoryEntry *dir_ent)
{	
	/* "/" 
	 * "/pizza"
	 * "/pizza/"
	 * "makedir pizza"
	 * "/pizza"
	 * "/pizza/"
	 * "makedir pizza2"
	 * "makedir pizza3"
	 * ...
	 * "makedir pizza6"
	 * should break on makedir pizza7
	 */
	int ret_val = 0;
	
	int disk_fd = open(disk_path, O_RDONLY, 0666);
	
	union SuperBlock sb = {}; 
	read(disk_fd, &sb, sizeof(union SuperBlock));
	
	union Block curr_block = {};
	set_block_offset(sb.info.root_block, disk_fd, sb);
	read(disk_fd, &curr_block, _BLOCK_SIZE);
	if (!strcmp(path, "/")) {
		memcpy(dir_ent, curr_block.block.dir_ents, sizeof(struct DirectoryEntry));
		close(disk_fd);
		return ret_val;
	}
	
	char *token = strtok((char *) path, "/");
	struct DirectoryEntry curr_dir_ent;
pathLoop:
	while (token != NULL) {
		for (int i = 0; i < _MAX_DIR_NUM; i++) {
			curr_dir_ent = curr_block.block.dir_ents[i];
			if (curr_dir_ent.in_use && !strcmp(token, curr_dir_ent.file_name)) {
				set_block_offset(curr_dir_ent.start_block, disk_fd, sb);
				read(disk_fd, &curr_block, _BLOCK_SIZE);
				token = strtok(NULL, "/");
				goto pathLoop;
			}
		}
		ret_val = -ENOENT;
		break;
	}
	memcpy(dir_ent, &curr_dir_ent, sizeof(struct DirectoryEntry));
	close(disk_fd);

	return ret_val;
}

void fill_stat(struct stat *stbuf, struct DirectoryEntry dir_ent) {
	struct fuse_context *context = fuse_get_context();
	stbuf->st_mode   = S_IFDIR | 0777;
	stbuf->st_atime  = time(0);
	stbuf->st_mtime  = time(0);
	stbuf->st_ino    = dir_ent.start_block;
	stbuf->st_nlink  = 1;
	stbuf->st_uid	 = (int) context->uid;
	stbuf->st_gid	 = (int) context->gid;
	stbuf->st_blocks = _BLOCK_SIZE / 512;
	stbuf->st_size   = _BLOCK_SIZE;
}

/* Write the FatEntry to it's position in the FAT, and then reset the
 * fd's position to where it was originally.
 */
void write_table_entry(int block_num, struct FatEntry entry, int disk_fd) {
	int orig_pos = lseek(disk_fd, 0, SEEK_CUR);
	int offset =  sizeof(union SuperBlock) + block_num*sizeof(struct FatEntry);
	lseek(disk_fd, offset, SEEK_SET);
	write(disk_fd, &entry, sizeof(struct FatEntry));
	lseek(disk_fd, orig_pos, SEEK_SET);
}

void read_table_entry(int block_num, struct FatEntry *entry, int disk_fd) {
	int orig_pos = lseek(disk_fd, 0, SEEK_CUR);
	int offset =  sizeof(union SuperBlock) + block_num*sizeof(struct FatEntry);
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
void create_root_block(union Block *root_bl) {
	memset(root_bl, 0, _BLOCK_SIZE);
	
	root_bl->block.in_use = 1;
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

void fill_new_block(union Block *new_block, char *file_name, int parent_block, union SuperBlock sb) {
	new_block->block.in_use = 1;
	new_block->block.start_block = sb.info.free_block;
	strcpy(new_block->block.file_name, file_name);

	// TODO: Figure out free list of blocks.
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
// ---------------------------------------------------

static void *fat_init(struct fuse_conn_info *conn) 
{
	// set absolute path to the backing file in disk_path
	// TODO: Unclear if needs to be relative or absolute path
	if (access(disk_path, F_OK) == -1) {
		// Zero out the entire disk and reset position.
		int disk_fd = open(disk_path, (O_RDWR | O_CREAT), 0666);
		char* FULL_DISK = (char *) malloc(_FAT_DISK_SIZE);
		memset(FULL_DISK, 0, _FAT_DISK_SIZE);
		ssize_t sz_res = write(disk_fd, &FULL_DISK, _FAT_DISK_SIZE);
		lseek(disk_fd, 0, SEEK_SET);

		// Create the Superblock and write it.
		union SuperBlock sb = {};
		create_SuperBlock(&sb);
		sz_res = write(disk_fd, &sb, _SUPERBLOCK_SIZE);

		// Check for errors
		if (sz_res < 0) {
			char *err_msg = "Error creating the super block\n";
			write(2, err_msg, strlen(err_msg));
			close(disk_fd);
			exit(0);
		} else if (sz_res != sizeof(sb)) {
			char *err_msg = "Super block not written to proper size.\n";
			write(2, err_msg, strlen(err_msg));
			close(disk_fd);			
			exit(0);			
		}
		
		// Create the root block and write it.
		union Block root_bl = {};
		memset(&root_bl, 0, sizeof(root_bl));
		create_root_block(&root_bl);
		set_block_offset(0, disk_fd, sb);
		lseek(disk_fd, 0, SEEK_CUR);
		
		// Check for errors while writing
		if (write(disk_fd, &root_bl, _BLOCK_SIZE) != _BLOCK_SIZE) {
			char *err_msg = "Root dir not written to proper size.\n";
			write(2, err_msg, strlen(err_msg));
			exit(0);
		}
		
		// Populate the table entries and write them
		struct FatEntry *table = malloc(sizeof(struct  FatEntry)*sb.info.n_blocks);
		create_FAT_table(table, sb);
		lseek(disk_fd, _SUPERBLOCK_SIZE, SEEK_SET);
		write(disk_fd, table, sizeof(struct FatEntry)*sb.info.n_blocks);
		lseek(disk_fd, 0, SEEK_SET);
		read(disk_fd, &sb, _SUPERBLOCK_SIZE);
		
		close(disk_fd);
		free(FULL_DISK);
		free(table);
	}
	return NULL;
}

static int fat_access(const char *path, int mask)
{
	struct DirectoryEntry dir_ent = {};
	int res = find_dir(path, &dir_ent);
	return res;
}


static int fat_getattr(const char *path, struct stat *stbuf)
{
	memset(stbuf, 0, sizeof(struct stat));
	struct DirectoryEntry dir_ent = {};
	int res = find_dir(path, &dir_ent);
	if (res == -ENOENT) {
		printf("in ENOENT\n");
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
	int res = find_dir(path, &parent_dir_ent);

	int disk_fd = open(disk_path, O_RDONLY, 0666);
	union SuperBlock sb = {};
	read(disk_fd, &sb, sizeof(union SuperBlock));

	if(!strcmp(path, "/")) {
		set_block_offset(sb.info.root_block, disk_fd, sb);
	} else {
		if(res == -ENOENT) {
			printf("ENOENT\n");
			return res;
		}
		set_block_offset(parent_dir_ent.start_block, disk_fd, sb);
	}
	
	union Block dir_block = {};
	read(disk_fd, &dir_block, sizeof(union Block));

	struct DirectoryEntry dir_ent = {};
	printf("offset: %d\n", offset);
	for (int i = offset; i < _MAX_DIR_NUM; i++) {
		dir_ent = dir_block.block.dir_ents[i];
		if (dir_ent.in_use) {
			printf("i: %d\n", i);
			int res = filler(buf, dir_ent.file_name, NULL, i+1);
			// TODO: Check if fuse can't handle that many requests
			// if (res ==)
		}
	}

	close(disk_fd);

	return 0;
}

static int fat_mkdir(const char *path, mode_t mode)
{
	char *tokens[100];
	tokens[0] = strtok((char *) path, "/");
	int i = 0;
	while(tokens[i] != NULL) {
		i++;
		tokens[i] = strtok(NULL, "/");
	}

	char *subpath = malloc(4096);
	for (int j = 0; j < i-1; j++) {
		strcat(subpath, "/");
		strcat(subpath, tokens[j]);
	}

	char *file_name = tokens[i-1];
	int disk_fd = open(disk_path, O_RDWR, 0666);
	
	union SuperBlock sb = {};
	read(disk_fd, &sb, sizeof(union SuperBlock));
	close(disk_fd);
	if (sb.info.free_block >= sb.info.n_blocks) {
		printf("in no space. %d >= %d \n", sb.info.free_block, sb.info.n_blocks);
		return -ENOSPC;
	} else if (strlen(file_name) >= _MAX_FILE_NAME_SZ) {
		return -ENAMETOOLONG;
	}

	struct DirectoryEntry dir_ent = {};
	int res = find_dir(subpath, &dir_ent);

	disk_fd = open(disk_path, O_RDWR);
	// When find_dir works (not looking to create in root directory)
	if(i > 1 && res == -ENOENT) {
		close(disk_fd);
		return res;
	} else if (i > 1) {
		set_block_offset(dir_ent.start_block, disk_fd, sb);		
	} else {
		set_block_offset(sb.info.root_block, disk_fd, sb);
	}

	// go to parent directory, insert entry
	union Block parent_block = {};
	read(disk_fd, &parent_block, _BLOCK_SIZE);

	struct DirectoryEntry parent_dir_ent = {};
	for (int i = 0; i < _MAX_DIR_NUM; i++) {
		parent_dir_ent = parent_block.block.dir_ents[i];
		if (!parent_dir_ent.in_use) {
			parent_dir_ent.in_use = 1;
			parent_dir_ent.start_block = sb.info.free_block;
			strcpy(parent_dir_ent.file_name, file_name);
			memcpy(&parent_block.block.dir_ents[i], &parent_dir_ent, sizeof(struct DirectoryEntry));
			break;
		}
		if (i == _MAX_DIR_NUM - 1) {
			close(disk_fd);
			return -ENOSPC;
		}
	}
	
	set_block_offset(dir_ent.start_block, disk_fd, sb);
	write(disk_fd, &parent_block, _BLOCK_SIZE);

	// Create the new block after the parent block.
	union Block new_block = {};
	fill_new_block(&new_block, file_name, dir_ent.start_block, sb);
	set_block_offset(new_block.block.start_block, disk_fd, sb);
	write(disk_fd, &new_block, _BLOCK_SIZE);
	
	// Update the FAT table for the newly added block, modify the SuperBlock to point to next free block
	struct FatEntry block_entry = {};
	read_table_entry(new_block.block.start_block, &block_entry, disk_fd);
	sb.info.free_block = block_entry.next;
	block_entry.next   = -1;
	block_entry.in_use = 1;
	write_table_entry(new_block.block.start_block, block_entry, disk_fd);

	// Write the newly updated SuperBlock
	lseek(disk_fd, 0, SEEK_SET);
	write(disk_fd, &sb, sizeof(union SuperBlock));
	close(disk_fd);	
	return 0;
}

static struct fuse_operations fat_oper = {
	.init       = fat_init,
	.access		= fat_access,
	.getattr	= fat_getattr,
	.readdir	= fat_readdir,
	.mkdir		= fat_mkdir,
};

int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &fat_oper, NULL);
}