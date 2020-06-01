##
## Makefile.am
##

noinst_HEADERS += tests/libutiltest/util_test_common.h

check_LTLIBRARIES += tests/libutiltest/libutiltest.la

utiltest_cppflags =
utiltest_libs = @libtest_link_dep@

utiltest_link = -L$(abs_builddir)/tests/libutiltest/.libs -lutiltest
utiltest_link_dep = $(utiltest_libs)

tests_libutiltest_libutiltest_la_SOURCES = tests/libutiltest/lib_test_common.c \
	tests/libutiltest/lib_test_log.c tests/libutiltest/lib_test_signal.c
tests_libutiltest_libutiltest_la_CPPFLAGS = $(AM_CPPFLAGS) -Isrc -Isrc/include \
	-Itests/libutiltest @libtest_cppflags@ $(utiltest_cppflags)
tests_libutiltest_libutiltest_la_CFLAGS = $(AM_CFLAGS)
tests_libutiltest_libutiltest_la_LIBADD = $(utiltest_libs)
tests_libutiltest_libutiltest_la_LDFLAGS = \
	-rpath @abs_top_builddir@/tests/libutiltest/.libs

## vi: set noexpandtab sw=4 ts=4:
