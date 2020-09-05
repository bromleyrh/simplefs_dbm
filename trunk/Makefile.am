##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

EXTRA_DIST = build-aux

noinst_HEADERS = back_end.h back_end_dbm.h blkdev.h common.h compat.h \
	fuse_cache.h obj.h ops.h request.h simplefs.h util.h

bin_PROGRAMS = mkfs.simplefs mount.simplefs simplefs simplefs_dbg

if SANITIZERS
AM_CPPFLAGS =
AM_CFLAGS = -ggdb3 -O0 @sanitizer@ -pipe -Wall -Wextra
else
if DEBUG
AM_CPPFLAGS =
AM_CFLAGS = -ggdb3 -O0 -pipe -Wall -Wextra
else
##AM_CPPFLAGS = -DNDEBUG
##AM_CFLAGS = -O2 -pipe -Wall -Wextra
AM_CPPFLAGS = -DNDEBUG
AM_CFLAGS = -ggdb3 -O0 -pipe -Wall -Wextra
endif

if LIBFUSE_3
defines = -DFUSE_USE_VERSION=32
else
defines = -DFUSE_USE_VERSION=26
endif

spec_to_h = scripts/spec_to_h.pl

BUILT_SOURCES =
check_LTLIBRARIES =
check_PROGRAMS =
TESTS =

CLEANFILES =

simplefs_SOURCES = back_end.c back_end_dbm.c blkdev.c compat.c fuse_cache.c \
	ops.c request.c simplefs.c util.c
simplefs_CPPFLAGS = $(AM_CPPFLAGS) $(defines) @fuse_cppflags@ @libutil_cppflags@
simplefs_CFLAGS = $(AM_CFLAGS)
simplefs_LDADD = @fuse_link_dep@ @libutil_link_dep@

mkfs_simplefs_SOURCES = mkfs.simplefs.c util.c
mkfs_simplefs_CPPFLAGS = $(AM_CPPFLAGS) @libutil_cppflags@
mkfs_simplefs_CFLAGS = $(AM_CFLAGS)
mkfs_simplefs_LDADD = -lreadline @libutil_link_dep@

mount_simplefs_SOURCES = mount.simplefs.c
mount_simplefs_CPPFLAGS = $(AM_CPPFLAGS)
mount_simplefs_CFLAGS = $(AM_CFLAGS)

simplefs_dbg_SOURCES = simplefs_dbg.c util.c
simplefs_dbg_CPPFLAGS = $(AM_CPPFLAGS) @libutil_cppflags@
simplefs_dbg_CFLAGS = $(AM_CFLAGS)
simplefs_dbg_LDADD = -lreadline @libutil_link_dep@

include scripts/Makefile.am
include tests/Makefile.am

install-exec-hook:
	ln -fs mount.simplefs $(bindir)/mount.simplefs-file

.PHONY: distclean-local

distclean-local:
	-rm -f scan_build

## vi: set noexpandtab sw=4 ts=4:
