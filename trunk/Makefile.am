##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

noinst_HEADERS = back_end.h common.h ops.h simplefs.h util.h

bin_PROGRAMS = simplefs

##if DEBUG
##AM_CFLAGS = -ggdb3 -O0 -pipe -Wall -Wextra
##else
##AM_CFLAGS = -DNDEBUG -O2 -pipe -Wall -Wextra
##endif

AM_CFLAGS = -DNDEBUG -ggdb3 -O0 -pipe -Wall -Wextra

simplefs_SOURCES = back_end.c ops.c simplefs.c util.c
simplefs_CFLAGS = $(AM_CFLAGS) -DFUSE_USE_VERSION=26 @fuse_cflags@ \
	@libutil_cflags@
simplefs_LDADD = @fuse_link_dep@ @libutil_link_dep@

## vi: set noexpandtab sw=4 ts=4:
