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

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#define _FAT_DISK_SIZE 10485760
#define _BLOCK_SIZE 4096

static const char *fat_disk_path = "fat_disk";
struct Superblock superblock;
struct Dir_entry dir_entry[4096/]
// TODO: Need to implement
/*static void *fat_init(struct fuse_conn_info *conn) {

}*/

// FIRST
static int fat_getattr(const char *path, struct stat *stbuf)
{
	int res;

	struct fuse_file_info *fi = {O_WRONLY | O_CREAT | O_TRUNC};
	int sb_fd = open(superblock_path, fi);
	char sb_buf[_BLOCK_SIZE];
	ssize_t sb_sz = read(sb_fd, sb_buf, _BLOCK_SIZE);
	
	if (sb_sz < 0) {
		write(2, "Error occured reading superblock");
		exit(0);
	}

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int fat_access(const char *path, int mask)
{
	int res;
	open(superblock_path, )
	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int fat_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
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

static int fat_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}


//#ifdef HAVE_SETXATTR
///* xattr operations are optional and can safely be left unimplemented */
//static int fat_setxattr(const char *path, const char *name, const char *value,
//			size_t size, int flags)
//{
//	int res = lsetxattr(path, name, value, size, flags);
//	if (res == -1)
//		return -errno;
//	return 0;
//}
//
//static int fat_getxattr(const char *path, const char *name, char *value,
//			size_t size)
//{
//	int res = lgetxattr(path, name, value, size);
//	if (res == -1)
//		return -errno;
//	return res;
//}
//
//static int fat_listxattr(const char *path, char *list, size_t size)
//{
//	int res = llistxattr(path, list, size);
//	if (res == -1)
//		return -errno;
//	return res;
//}
//
//static int fat_removexattr(const char *path, const char *name)
//{
//	int res = lremovexattr(path, name);
//	if (res == -1)
//		return -errno;
//	return 0;
//}
//
//
//#endif /* HAVE_SETXATTR */

static struct fuse_operations fat_oper = {
	.init       = fat_init,
	.getattr	= fat_getattr,
	.access		= fat_access,
	.readdir	= fat_readdir,
	.mkdir		= fat_mkdir,
/*#ifdef HAVE_SETXATTR
	.setxattr	= fat_setxattr,
	.getxattr	= fat_getxattr,
	.listxattr	= fat_listxattr,
	.removexattr	= fat_removexattr,
#endif*/
};

int main(int argc, char *argv[])
{
    umask(0);
	return fuse_main(argc, argv, &fat_oper, NULL);
}