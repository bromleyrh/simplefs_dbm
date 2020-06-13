/*
 * test_util_back_end_shell.h
 */

#ifndef _TEST_UTIL_BACK_END_SHELL_H
#define _TEST_UTIL_BACK_END_SHELL_H

#include "test_util_back_end.h"
#include "test_util_back_end_common.h"

#include <test_util.h>

#include <stdio.h>

struct be_cmd_args {
    int key;
};

struct be_cmd_data {
    void    *ctx;
    void    *iter;
    int     assert_key;
    int     verbose;
    int     (*search_back_end)(struct be_ctx *bectx, int key, int *res);
    int     (*dump_back_end)(FILE *f, struct be_ctx *bectx);
    int     (*print_stats)(FILE *f, struct be_ctx *bectx, int times);
    int     (*walk_back_end)(struct be_ctx *bectx);
    int     (*alloc_iter)(void **iter, struct be_ctx *bectx);
    int     (*free_iter)(void *iter);
    int     (*access_iter)(void *iter, int *res);
    int     (*increment_iter)(void *iter);
    int     (*decrement_iter)(void *iter);
    int     (*seek_iter)(void *iter, int key);
    int     (*seek_iter_idx)(void *iter, int idx);
};

LIBBACKENDTEST_EXPORTED cmd_t ins_cmd;
LIBBACKENDTEST_EXPORTED cmd_t del_cmd;

LIBBACKENDTEST_EXPORTED cmd_t find_cmd;
LIBBACKENDTEST_EXPORTED cmd_t select_cmd;
LIBBACKENDTEST_EXPORTED cmd_t rank_cmd;

LIBBACKENDTEST_EXPORTED cmd_t assert_cmd;

LIBBACKENDTEST_EXPORTED cmd_t dump_cmd;

LIBBACKENDTEST_EXPORTED cmd_t stat_cmd;

LIBBACKENDTEST_EXPORTED cmd_t walk_cmd;

LIBBACKENDTEST_EXPORTED cmd_t next_cmd;
LIBBACKENDTEST_EXPORTED cmd_t prev_cmd;
LIBBACKENDTEST_EXPORTED cmd_t search_cmd;
LIBBACKENDTEST_EXPORTED cmd_t isearch_cmd;
LIBBACKENDTEST_EXPORTED cmd_t reset_cmd;

LIBBACKENDTEST_EXPORTED int cmd_listen_cb_be(const char *, void *);

#endif

/* vi: set expandtab sw=4 ts=4: */
