/*
 * test_util_cont_ordered.h
 */

#ifndef _TEST_UTIL_CONT_ORDERED_H
#define _TEST_UTIL_CONT_ORDERED_H

#include "test_util_cont_common.h"

#include <test_util.h>

#include <stdint.h>
#include <stdio.h>

struct cont_stats_ordered {
    uint32_t num_keys;
};

typedef int test_walk_fn_ordered_t(void *, void *,
                                   int (*)(const void *, void *),
                                   void *, void *);

typedef int test_stats_fn_ordered_t(void *, struct cont_stats_ordered *);

struct cont_ctx_ordered {
    test_walk_fn_ordered_t  *test_walk;
    test_stats_fn_ordered_t *test_stats;
    int                     walk_resume_retval;
};

struct fn1_ctx {
    unsigned    key_size;
    unsigned    keys_found;
    int         prevkey;
};

struct fn2_ctx {
    unsigned    key_size;
    unsigned    keys_found;
    int         prevkey;
    int         walk_resume_test;
    int         walk_resume_retval;
};

struct fn3_ctx {
    struct bitmap_data  *bmdata;
    int                 bitmap_pos;
    unsigned            key_size;
    unsigned            keys_found;
    int                 prevkey;
    FILE                *checklog;
    int                 walk_resume_test;
    int                 walk_resume_retval;
};

typedef int walk_fn_ordered_t(const void *, void *);

extern LIBTESTCONT_EXPORTED walk_fn_ordered_t *fn1;
extern LIBTESTCONT_EXPORTED walk_fn_ordered_t *fn2;
extern LIBTESTCONT_EXPORTED walk_fn_ordered_t *fn3;

LIBTESTCONT_EXPORTED int verify_insertion_ordered(struct cont_ctx *contctx);

LIBTESTCONT_EXPORTED int verify_rand_ordered(struct cont_ctx *contctx);

#endif

/* vi: set expandtab sw=4 ts=4: */
