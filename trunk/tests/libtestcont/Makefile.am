##
## Makefile.am
##

EXTRA_DIST += tests/libtestcont/test_cont_config_gram.spec

noinst_HEADERS += tests/libtestcont/test_util_cont_cmdline.h \
	tests/libtestcont/test_util_cont_common.h \
	tests/libtestcont/test_util_cont_config.h \
	tests/libtestcont/test_util_cont_ordered.h \
	tests/libtestcont/test_util_cont_shell.h \
	tests/libtestcont/test_util_cont_util.h tests/libtestcont/test_util_cont.h

testcont_sp = test_cont_config_gram.spec
testcont_gram = TEST_CONT_CONFIG_GRAM

BUILT_SOURCES += tests/libtestcont/test_cont_config_gram_spec.h

CLEANFILES += tests/libtestcont/test_cont_config_gram_spec.h

tests/libtestcont/test_cont_config_gram_spec.h: tests/libtestcont/$(testcont_sp)
	$(spec_to_h) tests/libtestcont/$(testcont_sp) $(testcont_gram) > $@

check_LTLIBRARIES += tests/libtestcont/libtestcont.la

testcont_cppflags =
testcont_libs = @libjson_link_dep@ @libtest_link_dep@ $(testperf_link) \
	$(testperf_link_dep) $(testshell_link) $(testshell_link_dep) \
	$(utiltest_link) $(utiltest_link_dep)

testcont_link = -L$(abs_builddir)/tests/libtestcont/.libs -ltestcont
testcont_link_dep = $(testcont_libs)

tests_libtestcont_libtestcont_la_SOURCES = tests/libtestcont/test_util_cont.c \
	tests/libtestcont/test_util_cont_cmdline.c \
	tests/libtestcont/test_util_cont_config.c \
	tests/libtestcont/test_util_cont_cross_check.c \
	tests/libtestcont/test_util_cont_ordered.c \
	tests/libtestcont/test_util_cont_perf.c \
	tests/libtestcont/test_util_cont_shell.c \
	tests/libtestcont/test_util_cont_util.c util.c
tests_libtestcont_libtestcont_la_CPPFLAGS = $(AM_CPPFLAGS) -Isrc -Isrc/include \
	-Itests/libtestperf -Itests/libtestshell -Itests/libutiltest \
	-Itests/libtestcont @libjson_cppflags@ @libtest_cppflags@ \
	$(testcont_cppflags)
tests_libtestcont_libtestcont_la_CFLAGS = $(AM_CFLAGS)
tests_libtestcont_libtestcont_la_LIBADD = $(testcont_libs)
tests_libtestcont_libtestcont_la_LDFLAGS = \
	-rpath @abs_top_builddir@/tests/libtestcont/.libs
tests_libtestcont_libtestcont_la_DEPENDENCIES = \
	tests/libtestperf/libtestperf.la tests/libtestshell/libtestshell.la \
	tests/libutiltest/libutiltest.la

## vi: set noexpandtab sw=4 ts=4:
