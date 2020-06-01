/*
 * test_util_cont_shell.h
 */

#ifndef _TEST_UTIL_CONT_SHELL_H
#define _TEST_UTIL_CONT_SHELL_H

#include "test_util_cont.h"
#include "test_util_cont_common.h"

#include <test_util.h>

#include <stdio.h>

struct cont_cmd_args {
    int key;
};

struct cont_cmd_data {
    void    *ctx;
    void    *iter;
    int     assert_key;
    int     verbose;
    int     (*search_container)(struct cont_ctx *contctx, int key, int *res);
    int     (*dump_container)(FILE *f, struct cont_ctx *contctx);
    int     (*print_stats)(FILE *f, struct cont_ctx *contctx, int times);
    int     (*walk_container)(struct cont_ctx *contctx);
    int     (*alloc_iter)(void **iter, struct cont_ctx *contctx);
    int     (*free_iter)(void *iter);
    int     (*access_iter)(void *iter, int *res);
    int     (*increment_iter)(void *iter);
    int     (*decrement_iter)(void *iter);
    int     (*seek_iter)(void *iter, int key);
    int     (*seek_iter_idx)(void *iter, int idx);
};

LIBTESTCONT_EXPORTED cmd_t ins_cmd;
LIBTESTCONT_EXPORTED cmd_t del_cmd;

LIBTESTCONT_EXPORTED cmd_t find_cmd;
LIBTESTCONT_EXPORTED cmd_t select_cmd;
LIBTESTCONT_EXPORTED cmd_t rank_cmd;

LIBTESTCONT_EXPORTED cmd_t assert_cmd;

LIBTESTCONT_EXPORTED cmd_t dump_cmd;

LIBTESTCONT_EXPORTED cmd_t stat_cmd;

LIBTESTCONT_EXPORTED cmd_t walk_cmd;

LIBTESTCONT_EXPORTED cmd_t next_cmd;
LIBTESTCONT_EXPORTED cmd_t prev_cmd;
LIBTESTCONT_EXPORTED cmd_t search_cmd;
LIBTESTCONT_EXPORTED cmd_t isearch_cmd;
LIBTESTCONT_EXPORTED cmd_t reset_cmd;

LIBTESTCONT_EXPORTED int cmd_listen_cb_cont(const char *, void *);

#endif

/* vi: set expandtab sw=4 ts=4: */
