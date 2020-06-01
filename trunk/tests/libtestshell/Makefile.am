##
## Makefile.am
##

noinst_HEADERS += tests/libtestshell/test_util_shell.h

check_LTLIBRARIES += tests/libtestshell/libtestshell.la

testshell_cppflags =
testshell_libs = @libtest_link_dep@ $(utiltest_link) $(utiltest_link_dep)

testshell_link = -L$(abs_builddir)/tests/libtestshell/.libs -ltestshell \
	$(testshell_libs)
testshell_link_dep = $(testshell_libs)

tests_libtestshell_libtestshell_la_SOURCES = \
	tests/libtestshell/test_util_shell.c
tests_libtestshell_libtestshell_la_CPPFLAGS = $(AM_CPPFLAGS) -Isrc \
	-Isrc/include -Itests/libtestshell -Itests/libutiltest @libtest_cppflags@ \
	$(testshell_cppflags)
tests_libtestshell_libtestshell_la_CFLAGS = $(AM_CFLAGS)
tests_libtestshell_libtestshell_la_LIBADD = $(testshell_libs)
tests_libtestshell_libtestshell_la_LDFLAGS = \
	-rpath @abs_top_builddir@/tests/libtestshell/.libs
tests_libtestshell_libtestshell_la_DEPENDENCIES = \
	tests/libutiltest/libutiltest.la

## vi: set noexpandtab sw=4 ts=4:
