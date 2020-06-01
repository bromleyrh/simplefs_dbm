/*
 * util_test_common.h
 */

#ifndef _UTIL_TEST_COMMON_H
#define _UTIL_TEST_COMMON_H

#define EXPORTED __attribute__((__visibility__("default")))

#include <stdio.h>

#define OUTWIN "outwin"
#define INFOWIN1 "infowin1"
#define INFOWIN2 "infowin2"

extern const char *checklogprefix;
extern const char *logprefix;
extern FILE **testlogp;

EXPORTED FILE *open_log_file(int checklog);
EXPORTED int close_log_file(FILE *f);
EXPORTED void show_log_names(void);

EXPORTED void test_segv_handler(FILE *log);

EXPORTED int change_to_tmpdir(const char *template);

#endif

/* vi: set expandtab sw=4 ts=4: */
