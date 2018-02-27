/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags --libs` fusefat.c -o fusefat
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

static const char *fat_disk_path = "fat_disk";

// has '/' at the end.
static char mountpoint[1024];
union SuperBlock sb = {};
struct BlockNode *free_list = NULL;
union Block table[(_FAT_DISK_SIZE/_BLOCK_SIZE)-1];

// ----------------------------------------------------
// Helper methods

void get_abs_path(const char *path, char *dest) {
	if (*path == '/') {
		path++;
	}
	strcpy(dest, mountpoint);
	strcat(dest, path);
}

// ---------------------------------------------------

static void *fat_init(struct fuse_conn_info *conn) {
	char full_disk_path[1024];
	get_abs_path(fat_disk_path, full_disk_path);
	
	if (access(full_disk_path, F_OK) == -1) {
		sb.s.n_blocks = (uint32_t) _FAT_DISK_SIZE/_BLOCK_SIZE;
		sb.s.block_sz = _BLOCK_SIZE;
		
		int disk_fd = open(full_disk_path, (O_RDWR | O_CREAT | O_TRUNC));
		ssize_t sz_res = write(disk_fd, &sb, sizeof(_SUPERBLOCK_SIZE));
		if (sz_res < 0) {
			char *err_msg = "Error creating the super block\n";
			write(2, err_msg, strlen(err_msg));
			exit(0);
		}

		union Block root_block = {};
		*(root_block.b.file_name) = '/';
		root_block.b.in_use = 1;
		ssize_t sz_block = write(disk_fd, &root_block, sizeof(_BLOCK_SIZE));
		printf("before assignment\n");
		table[0] = root_block;
		sb.s.root_block = 0;
		
		// Account all free blocks (only not the root)
		for (int i=1; i < sb.s.n_blocks-1; i++) {
			printf("allocating free blocks %d\n", i);
			union Block empty_block = {};
			empty_block.b.in_use=0;
			table[i] = empty_block;

			struct BlockNode head = {head.data=i, head.next=free_list};
			free_list = &head;
		}
		close(disk_fd);
	}
	return NULL;
}

// TODO: testing.
static int fat_getattr(const char *path, struct stat *stbuf)
{
	for (int i = 0; i < sb.s.n_blocks-1; i++) {
		printf("searching for path\n");
		if (table[i].b.in_use && strcmp(table[i].b.file_name, path)) {
			stbuf->st_size = table[i].b.file_size;
			// these should probably change
			stbuf->st_mode = S_IFDIR | 0777;		
			stbuf->st_nlink = 2;
			break;
		}
	}
	return 0;
}

// TODO: Just necessary to run. Does this need more?
static int fat_access(const char *path, int mask)
{
	return 0;
}

static int fat_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	char abs_path[1024];
	get_abs_path(path, abs_path);

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	char *token;
	char *rest = path;
	union Block curr = table[sb.s.root_block];
	int i = 0;
	while ((token = strtok_r(rest, "/", &rest))) {
		for (int e=0; e < _DIR_SIZE; e++) {
			int32_t curr_entry = curr.b.fat_entry[e];
			if (curr_entry >= 0 && 
				table[curr_entry].b.in_use &&
				strncmp(table[curr_entry].b.file_name, token, strlen(token)))
			{
				curr = table[curr_entry];
				break;
			}
			if (e == _DIR_SIZE-1) {
				return -ENOENT;
			}
		}
		i++;
	}

	for (int i=0; i < _DIR_SIZE; i++) {
		int32_t curr_entry = curr.b.fat_entry[i];
		if (curr_entry >= 0 && table[curr_entry].b.in_use) {
			filler(buf, table[curr_entry].b.file_name, NULL, 0);
		}
	}
	
	return 0;
}

static int fat_mkdir(const char *path, mode_t mode)
{
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static struct fuse_operations fat_oper = {
	.init       = fat_init,
	.getattr	= fat_getattr,
	.access		= fat_access,
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