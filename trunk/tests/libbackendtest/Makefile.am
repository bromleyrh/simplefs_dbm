##
## Makefile.am
##

EXTRA_DIST += tests/libbackendtest/test_back_end_config_gram.spec

noinst_HEADERS += tests/libbackendtest/test_util_back_end_cmdline.h \
	tests/libbackendtest/test_util_back_end_common.h \
	tests/libbackendtest/test_util_back_end_config.h \
	tests/libbackendtest/test_util_back_end_ordered.h \
	tests/libbackendtest/test_util_back_end_shell.h \
	tests/libbackendtest/test_util_back_end_util.h \
	tests/libbackendtest/test_util_back_end.h

backendtest_sp = test_back_end_config_gram.spec
backendtest_gram = BACK_END_TEST_CONFIG_GRAM

BUILT_SOURCES += tests/libbackendtest/test_back_end_config_gram_spec.h

CLEANFILES += tests/libbackendtest/test_back_end_config_gram_spec.h

tests/libbackendtest/test_back_end_config_gram_spec.h: \
	tests/libbackendtest/$(backendtest_sp)
	$(spec_to_h) "tests/libbackendtest/$(backendtest_sp)" $(backendtest_gram) \
		> $@

check_LTLIBRARIES += tests/libbackendtest/libbackendtest.la

backendtest_cppflags =
backendtest_libs = @libjson_link_dep@ @libtest_link_dep@ $(testperf_link) \
	$(testperf_link_dep) $(testshell_link) $(testshell_link_dep) \
	$(utiltest_link) $(utiltest_link_dep)

backendtest_link = -L$(abs_builddir)/tests/libbackendtest/.libs -lbackendtest
backendtest_link_dep = $(backendtest_libs)

tests_libbackendtest_libbackendtest_la_SOURCES = \
	tests/libbackendtest/test_util_back_end.c \
	tests/libbackendtest/test_util_back_end_cmdline.c \
	tests/libbackendtest/test_util_back_end_config.c \
	tests/libbackendtest/test_util_back_end_cross_check.c \
	tests/libbackendtest/test_util_back_end_ordered.c \
	tests/libbackendtest/test_util_back_end_perf.c \
	tests/libbackendtest/test_util_back_end_shell.c \
	tests/libbackendtest/test_util_back_end_util.c util.c
tests_libbackendtest_libbackendtest_la_CPPFLAGS = $(AM_CPPFLAGS) -Isrc \
	-Isrc/include -Itests/libtestperf -Itests/libtestshell -Itests/libutiltest \
	-Itests/libbackendtest @libjson_cppflags@ @libtest_cppflags@ \
	$(backendtest_cppflags)
tests_libbackendtest_libbackendtest_la_CFLAGS = $(AM_CFLAGS)
tests_libbackendtest_libbackendtest_la_LIBADD = $(backendtest_libs)
tests_libbackendtest_libbackendtest_la_LDFLAGS = \
	-rpath @abs_top_builddir@/tests/libbackendtest/.libs
tests_libbackendtest_libbackendtest_la_DEPENDENCIES = \
	tests/libtestperf/libtestperf.la tests/libtestshell/libtestshell.la \
	tests/libutiltest/libutiltest.la

## vi: set noexpandtab sw=4 ts=4:
