/*
 * test_util_cont_cmdline.h
 */

#ifndef _TEST_UTIL_CONT_CMDLINE_H
#define _TEST_UTIL_CONT_CMDLINE_H

const char *cont_test_usage(const char *progusage, int order_stats);
const char *cont_test_opt_str(const char *test_opt_str, int order_stats);

int parse_cont_test_opt(int opt, void *test_opts);

#endif

/* vi: set expandtab sw=4 ts=4: */
