##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

check_PROGRAMS += tests/fuse_cache_test tests/rem_dir_creat_test

include tests/libtestperf/Makefile.am

include tests/libtestcont/Makefile.am

include tests/libtestshell/Makefile.am
include tests/libutiltest/Makefile.am

tests_fuse_cache_test_SOURCES = back_end.c back_end_dbm.c fuse_cache.c \
	tests/fuse_cache_test.c
tests_fuse_cache_test_CPPFLAGS = $(AM_CPPFLAGS) -Itests/libtestcont \
	-Itests/libutiltest @libtest_cppflags@
tests_fuse_cache_test_CFLAGS = $(AM_CFLAGS)
tests_fuse_cache_test_LDADD = $(testcont_link) $(testcont_link_dep) \
	$(utiltest_link) $(utiltest_link_dep) @libtest_link_dep@
tests_fuse_cache_test_LDFLAGS = $(AM_LDFLAGS)
tests_fuse_cache_test_DEPENDENCIES = tests/libtestcont/libtestcont.la \
	tests/libutiltest/libutiltest.la

tests_rem_dir_creat_test_SOURCES = tests/rem_dir_creat_test.c
tests_rem_dir_creat_test_CPPFLAGS = $(AM_CPPFLAGS)
tests_rem_dir_creat_test_CFLAGS = $(AM_CFLAGS)

## vi: set noexpandtab sw=4 ts=4:
