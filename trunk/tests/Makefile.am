##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

EXTRA_DIST += tests/defs

check_PROGRAMS += tests/fuse_cache_test tests/rem_dir_creat_test

TESTS_ENVIRONMENT = TESTDIR=tests; export TESTDIR;

defs = tests/defs

TESTS += $(defs)/fuse_cache_test.sh

include tests/libtestperf/Makefile.am

include tests/libbackendtest/Makefile.am

include tests/libtestshell/Makefile.am
include tests/libutiltest/Makefile.am

tests_fuse_cache_test_SOURCES = back_end.c back_end_dbm.c blkdev.c \
	fuse_cache.c tests/fuse_cache_test.c
tests_fuse_cache_test_CPPFLAGS = $(AM_CPPFLAGS) -Itests/libbackendtest \
	-Itests/libutiltest @libtest_cppflags@
tests_fuse_cache_test_CFLAGS = $(AM_CFLAGS)
tests_fuse_cache_test_LDADD = $(backendtest_link) $(backendtest_link_dep) \
	$(utiltest_link) $(utiltest_link_dep) @libtest_link_dep@
tests_fuse_cache_test_LDFLAGS = $(AM_LDFLAGS)
tests_fuse_cache_test_DEPENDENCIES = tests/libbackendtest/libbackendtest.la \
	tests/libutiltest/libutiltest.la

tests_rem_dir_creat_test_SOURCES = tests/rem_dir_creat_test.c
tests_rem_dir_creat_test_CPPFLAGS = $(AM_CPPFLAGS)
tests_rem_dir_creat_test_CFLAGS = $(AM_CFLAGS)

## vi: set noexpandtab sw=4 ts=4:
