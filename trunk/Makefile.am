##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

EXTRA_DIST = build-aux

noinst_HEADERS = back_end.h back_end_dbm.h blkdev.h common.h compat.h \
	fuse_cache.h obj.h ops.h request.h simplefs.h util.h

bin_PROGRAMS = mkfs.simplefs mount.simplefs simplefs simplefs_dbg \
	umount.simplefs

defines :=
if COVERAGE_ANALYSIS
defines += -DCODE_COVERAGE_ANALYSIS
endif

if COVERAGE_ANALYSIS
debug_cppflags_debug =
debug_cflags_debug = -g -O0

debug_cppflags_ndebug = -DNDEBUG
debug_cflags_ndebug = -g -O0

coverage_analysis_cflags = -fprofile-arcs -ftest-coverage
else
debug_cppflags_debug =
debug_cflags_debug = -ggdb3 -O0

debug_cppflags_ndebug = -DNDEBUG
##debug_cflags_ndebug = -O2
debug_cflags_ndebug = -ggdb3 -O0

coverage_analysis_cflags =
endif

if SANITIZERS
AM_CPPFLAGS = $(defines) $(debug_cppflags_debug)
AM_CFLAGS = $(debug_cflags_debug) $(coverage_analysis_cflags) @sanitizer@ \
	-pipe -Wall -Wextra
else
if DEBUG
AM_CPPFLAGS = $(defines) $(debug_cppflags_debug)
AM_CFLAGS = $(debug_cflags_debug) $(coverage_analysis_cflags) -pipe -Wall \
	-Wextra
else
AM_CPPFLAGS = $(defines) $(debug_cppflags_ndebug)
AM_CFLAGS = $(debug_cflags_ndebug) -pipe -Wall -Wextra
endif
endif

if LIBFUSE_3
fuse_defines = -DFUSE_USE_VERSION=32
else
fuse_defines = -DFUSE_USE_VERSION=26
endif

spec_to_h = scripts/spec_to_h.pl

BUILT_SOURCES =
check_LTLIBRARIES =
check_PROGRAMS =
TESTS =

CLEANFILES =

simplefs_SOURCES = back_end.c back_end_dbm.c blkdev.c compat.c fuse_cache.c \
	ops.c request.c simplefs.c util.c
simplefs_CPPFLAGS = $(AM_CPPFLAGS) $(fuse_defines) @fuse_cppflags@ \
	@libutil_cppflags@
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

umount_simplefs_SOURCES = umount.simplefs.c
umount_simplefs_CPPFLAGS = $(AM_CPPFLAGS)
umount_simplefs_CFLAGS = $(AM_CFLAGS)

include scripts/Makefile.am
include tests/Makefile.am

install-exec-hook:
	ln -fs mount.simplefs $(bindir)/mount.simplefs-file

.PHONY: distclean-local

distclean-local:
	-rm -f scan_build

## vi: set noexpandtab sw=4 ts=4:
