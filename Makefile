CC	=	gcc
SHELL   =	/bin/sh
CFLAGS  =	-g -Og $(PKGFLAGS)

PKGFLAGS        =	`pkg-config fuse --cflags --libs`

fat.o : fat.c
	gcc -Wall -o fat fat.c -g -Og $(PKGFLAGS)