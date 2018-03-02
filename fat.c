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
#include "fat_structs.h"

/*
 * TODOs:
 * Correct number of hard links
 */

// has '/' at the end.
static char mountpoint[1024];

// absolute path to the disk backing file
static char *disk_path = "/tmp/fat_disk";

// ----------------------------------------------------
// Helper methods

// Get the absolute path of a relative path, using the mountpoint found at runtime.
// TODO: requires some rethinking.
void get_abs_path(const char *path, char *dest)
{
	if (*path == '/') {
		path++;
	}
	strcpy(dest, mountpoint);
	strcat(dest, path);
}

// Set File Descriptor offset to be at the beginning of a block
void set_block_offset(int block_num, int disk_fd, union SuperBlock sb)
{
	int offset = _SUPERBLOCK_SIZE + sb.info.root_block*_BLOCK_SIZE + block_num*_BLOCK_SIZE;
	lseek(disk_fd, offset, SEEK_SET);
}

int find_dir(const char *path, struct DirectoryEntry *dir_ent)
{
	int ret_val = 0;
	
	int disk_fd = open(disk_path, O_RDONLY);
	union SuperBlock sb = {}; 
	read(disk_fd, &sb, _SUPERBLOCK_SIZE);sx
	int block_num = sb.info.root_block;
	
	char *token = strtok((char *) path, "/");
	
	if (path[0] == '/' && strlen(path) == 1) {
		set_block_offset(block_num, disk_fd, sb);
	} else if (path[0] == '/') path++;
	
pathLoop:
	while (token != NULL) {
		for (int i = 0; i < _MAX_DIR_NUM; i++) {
			read(disk_fd, dir_ent, sizeof(*dir_ent));
			if (dir_ent->in_use && strcmp(token, dir_ent->file_name)) {
				block_num = dir_ent->start_block;
				set_block_offset(block_num, disk_fd, sb);
				token = strtok(NULL, "/");
				goto pathLoop;
			}
			printf(dir_ent.file_name);
		}
		ret_val = -ENOENT;
	}
	close(disk_fd);
	return ret_val;	
}

void fill_stat(struct stat *stbuf, struct DirectoryEntry dir_ent) {
	struct fuse_context *context = fuse_get_context();
	stbuf->st_mode   = S_IFDIR | 0777;
	stbuf->st_atime  = dir_ent.last_access;
	stbuf->st_mtime  = dir_ent.last_modification;
	stbuf->st_nlink  = 1;
	stbuf->st_uid	 = (int) context->uid;
	stbuf->st_gid	 = (int) context->gid;
	stbuf->st_blocks = _BLOCK_SIZE / 512;
}

// ---------------------------------------------------

static void *fat_init(struct fuse_conn_info *conn) 
{
	// set absolute path to the backing file in disk_path
	// TODO: Unclear if needs to be relative or absolute path
	if (access(disk_path, F_OK) == -1) {
		union SuperBlock sb = {};	
		sb.info.magic_num = _MAGIC_NUM;
		sb.info.root_block = 0;
		sb.info.free_block = 1;
		sb.info.block_size = _BLOCK_SIZE;
		sb.info.n_blocks = (_FAT_DISK_SIZE - _SUPERBLOCK_SIZE) / _BLOCK_SIZE;
		
		int disk_fd = open(disk_path, (O_RDWR | O_CREAT));
		ssize_t sz_res = write(disk_fd, &sb, _SUPERBLOCK_SIZE);
		if (sz_res < 0) {
			char *err_msg = "Error creating the super block\n";
			write(2, err_msg, strlen(err_msg));
			exit(0);
		} else if (sz_res != sizeof(sb)) {
			char *err_msg = "Super block not written to proper size.\n";
			write(2, err_msg, strlen(err_msg));
			exit(0);			
		}

		// Write 0's to the rest of the table, and reset to end of SuperBlock.
		char z = 0;
		for (int b = sizeof(sb); b < _FAT_DISK_SIZE; b++) {
			write(disk_fd, &z, sizeof(char));
		}
		lseek(disk_fd, sizeof(sb), SEEK_SET);

		// Write root directories self reference and parent after the superblock in backing file.
		struct DirectoryEntry root = {};
		root.in_use = 1;
		strcpy(root.file_name, ".");
		root.start_block = 0;
		root.file_length = 0;
		
		
		if (write(disk_fd, &root, sizeof(root)) != sizeof(root)) {
			char *err_msg = "Root dir not written to proper size.\n";
			write(2, err_msg, strlen(err_msg));
			exit(0);
		}

		struct DirectoryEntry root_parent = {};
		root_parent.in_use = 1;
		strcpy(root_parent.file_name, "..");
		root.start_block = 0;
		root.file_length = 0;
		
		if (write(disk_fd, &root_parent, sizeof(root_parent)) != sizeof(root_parent)) {
			char *err_msg = "Root dir not written to proper size.\n";
			write(2, err_msg, strlen(err_msg));
			exit(0);
		}

		close(disk_fd);
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
	struct DirectoryEntry dir_ent = {};
	int res = find_dir(path, &dir_ent);
	if(res == -ENOENT) {
		return res;
	}
	
	for (int i = 0; i < _MAX_DIR_NUM; i++) {
		if (dir_ent.in_use) {
			struct stat stbuf = {};
			fill_stat(&stbuf, dir_ent);
			filler(buf, dir_ent.file_name, &stbuf, dir_ent.start_block);
		}
	}
	return 0;
}

static int fat_mkdir(const char *path, mode_t mode)
{
	int last_slash;
	short past_final_slashes = 0;
	for (int i=strlen(path)-1; i >= 0; i++) {
		// last char of path is /, ignore it
		if (!past_final_slashes && path[i] == '/') {
			continue;
		} else if(!past_final_slashes && path[i] != '/') {
			past_final_slashes = 1;
			continue;
		}

		if (path[i] == '/') {
			last_slash = i;
			break;
		}
	}

	char *subpath = malloc(strlen(path));
	memcpy(subpath, path, last_slash);
	subpath[last_slash+1] = '\0';
	
	struct DirectoryEntry dir_ent = {};
	find_dir(subpath, &dir_ent);

	int disk_fd = open(disk_path, O_RDWR);
	union SuperBlock sb = {};
	read(disk_fd, &sb, sizeof(_SUPERBLOCK_SIZE));	
	if (sb.info.free_block >= _SUPERBLOCK_SIZE) {
		close(disk_fd);
		return -ENOSPC;
	} else if (strlen(path) - last_slash + 1 > _MAX_FILE_NAME_SZ) {
		close(disk_fd);
		return -ENAMETOOLONG;
	}

	// use the first '.' entry 
	set_block_offset(dir_ent.start_block, disk_fd, sb);
	int parent_block = dir_ent.start_block;

	time_t curr_time = time(0);	
	for (int i = 0; i < _MAX_DIR_NUM; i++) {
		if (!dir_ent.in_use) {
			dir_ent.in_use = 1;
			dir_ent.start_block = sb.info.free_block;
			memcpy(dir_ent.file_name, path+last_slash+1, strlen(path)-last_slash+1);

			dir_ent.last_access = (long) curr_time;
			dir_ent.last_modification = (long) curr_time;
		}
		if (i == _MAX_DIR_NUM - 1) {
			return -ENOSPC;
		}
		read(disk_fd, &dir_ent, sizeof(_SUPERBLOCK_SIZE));
	}

	union EmptyBlock free_block = {};
	set_block_offset(sb.info.free_block, disk_fd, sb);
	read(disk_fd, &free_block, sizeof(_BLOCK_SIZE));
	int curr_block = sb.info.free_block;
	sb.info.free_block = free_block.info.free_block;
	set_block_offset(curr_block, disk_fd, sb);
	// ...
	struct DirectoryEntry self_dir = {};
	char *self_name   = ".";
	memcpy(self_dir.file_name, self_name, strlen(self_name));	
	self_dir.in_use 	 = 1;
	self_dir.start_block = curr_block;
	self_dir.last_access = (long) curr_time;
	self_dir.last_modification = (long) curr_time;
	write(disk_fd, &self_dir, sizeof(self_dir));

	struct DirectoryEntry parent_dir = {};
	char *parent_name = "..";
	memcpy(parent_dir.file_name, parent_name, strlen(parent_name));
	parent_dir.in_use 	   = 1;
	parent_dir.start_block = parent_block;
	parent_dir.last_access = (long) curr_time;
	parent_dir.last_modification = (long) curr_time;
	write(disk_fd, &parent_dir, sizeof(parent_dir));

	lseek(disk_fd, 0, SEEK_SET);
	write(disk_fd, &sb, sizeof(_SUPERBLOCK_SIZE));
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
	realpath(argv[1], mountpoint);
	strcat(mountpoint, "/");
	printf("Mounting on %s\n", mountpoint);
	return fuse_main(argc, argv, &fat_oper, NULL);
}