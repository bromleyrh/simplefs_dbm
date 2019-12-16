##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

noinst_HEADERS = back_end.h common.h ops.h simplefs.h util.h

bin_PROGRAMS = mount.simplefs simplefs

##if DEBUG
##AM_CPPFLAGS =
##AM_CFLAGS = -ggdb3 -O0 -pipe -Wall -Wextra
##else
##AM_CPPFLAGS = -DNDEBUG
##AM_CFLAGS = -O2 -pipe -Wall -Wextra
##endif

if DEBUG
AM_CPPFLAGS =
AM_CFLAGS = -ggdb3 -O0 -pipe -Wall -Wextra
else
AM_CPPFLAGS = -DNDEBUG
AM_CFLAGS = -ggdb3 -O0 -pipe -Wall -Wextra
endif

if LIBFUSE_3
defines = -DFUSE_USE_VERSION=32
else
defines = -DFUSE_USE_VERSION=26
endif

simplefs_SOURCES = back_end.c ops.c simplefs.c util.c
simplefs_CPPFLAGS = $(AM_CPPFLAGS) $(defines) @fuse_cppflags@ @libutil_cppflags@
simplefs_CFLAGS = $(AM_CFLAGS)
simplefs_LDADD = @fuse_link_dep@ @libutil_link_dep@

mount_simplefs_SOURCES = mount.simplefs.c
mount_simplefs_CPPFLAGS = $(AM_CPPFLAGS)
mount_simplefs_CFLAGS = $(AM_CFLAGS)

EXTRA_DIST = build-aux

include scripts/Makefile.am

distclean-local:
	-rm -f scan_build

## vi: set noexpandtab sw=4 ts=4:
