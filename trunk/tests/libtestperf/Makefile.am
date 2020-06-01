##
## Makefile.am
##

noinst_HEADERS += tests/libtestperf/test_util_perf_common.h \
	tests/libtestperf/test_util_perf.h

check_LTLIBRARIES += tests/libtestperf/libtestperf.la

testperf_cppflags =
testperf_libs =

testperf_link = -L$(abs_builddir)/tests/libtestperf/.libs -ltestperf
testperf_link_dep = $(testperf_libs)

tests_libtestperf_libtestperf_la_SOURCES = tests/libtestperf/test_util_perf.c
tests_libtestperf_libtestperf_la_CPPFLAGS = $(AM_CPPFLAGS) -Isrc -Isrc/include \
	-Itests/libtestperf $(testperf_cppflags)
tests_libtestperf_libtestperf_la_CFLAGS = $(AM_CFLAGS)
tests_libtestperf_libtestperf_la_LIBADD = $(testperf_libs)
tests_libtestperf_libtestperf_la_LDFLAGS = \
	-rpath @abs_top_builddir@/tests/libtestperf/.libs

## vi: set noexpandtab sw=4 ts=4:
