/*
 * test_util_back_end_perf.c
 */

#include "bitmap.h"
#include "test_util_back_end.h"
#include "test_util_back_end_util.h"
#include "test_util_perf.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <test_util.h>

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

struct be_perf_test_args {
    struct be_ctx           *bectx;
    const struct be_params  *bep;
    int                     (*reset_be)(struct be_ctx *);
    unsigned                nops;
    unsigned                n;
    unsigned                nelem;
    unsigned                epsilon;
    unsigned                limit_lower;
    unsigned                limit_upper;
};

#define EPSILON 8

#define NUM_PERF_TEST_OPS (4 * 1024 * 1024)

static int be_perf_test_init_ctx(void **, void *);
static int be_perf_test_destroy_ctx(void *);
static int be_perf_test_prepare_test(void *, void *);
static int be_perf_test_do_op(void *);
static int be_perf_test_end_test(void *);

static const struct perf_test_ops be_perf_test_ops = {
    .init_ctx       = be_perf_test_init_ctx,
    .destroy_ctx    = be_perf_test_destroy_ctx,
    .prepare_test   = be_perf_test_prepare_test,
    .do_op          = be_perf_test_do_op,
    .end_test       = be_perf_test_end_test
};

static int
be_perf_test_init_ctx(void **ctx, void *args)
{
    *ctx = args;

    return 0;
}

static int
be_perf_test_destroy_ctx(void *ctx)
{
    (void)ctx;

    return 0;
}

static int
be_perf_test_prepare_test(void *ctx, void *args)
{
    const struct be_params *bep;
    int (*gen_key_fn)(int, int);
    int ret;
    struct be_ctx *bectx;
    struct be_perf_test_args *targs = ctx;
    unsigned n;

    bectx = targs->bectx;
    bep = targs->bep;

    gen_key_fn = bep->zero_keys ? &gen_key : &gen_key_no_zero;

    n = 0;
    while (n < (uintptr_t)args) {
        int key = (*gen_key_fn)(bep->max_key, params.out_of_range_period);

        ret = be_insert(bectx, key, NULL, 1, 0, 0);
        if (ret != 0) {
            if (ret != -EADDRINUSE)
                return ret;
            continue;
        }
        ++n;
    }
    targs->nops = 0;
    targs->n = targs->nelem = n;

    targs->limit_lower = n - EPSILON;
    targs->limit_upper = n + EPSILON;
    targs->epsilon = EPSILON;

    return 0;
}

static int
be_perf_test_do_op(void *ctx)
{
    const struct be_params *bep;
    enum {
        DELETE = 0,
        SEARCH = 1,
        INSERT = 2
    } op;
    int (*gen_key_fn)(int, int);
    int key;
    int lower_bound, upper_bound;
    int ret;
    struct be_ctx *bectx;
    struct be_perf_test_args *targs = ctx;

    bectx = targs->bectx;
    bep = targs->bep;

    gen_key_fn = bep->zero_keys ? &gen_key : &gen_key_no_zero;

    lower_bound = targs->nelem <= targs->limit_lower;
    upper_bound = targs->nelem >= targs->limit_upper;

    op = lower_bound + random() % (lower_bound || upper_bound ? 2 : 3);

    key = (*gen_key_fn)(bep->max_key, 0);

    switch (op) {
    case DELETE:
        ret = be_delete(bectx, key, NULL, 1, 0, 0);
        if (ret != 0) {
            if (ret != -EADDRNOTAVAIL)
                return ret;
        } else
            --targs->nelem;
        break;
    case SEARCH:
        ret = bep->test_range_search && random() % 2 == 0
              ? be_range_find(bectx, key, NULL, 0, 0)
              : be_find(bectx, key, NULL, 0, 0);
        if (ret < 0)
            return ret;
        break;
    case INSERT:
        ret = be_insert(bectx, key, NULL, 1, 0, 0);
        if (ret != 0) {
            if (ret != -EADDRINUSE)
                return ret;
        } else
            ++targs->nelem;
        break;
    default:
        return -EIO;
    }

    infomsgf("\rn == %u: %u", targs->n, targs->nops);

    return ++targs->nops == NUM_PERF_TEST_OPS;
}

static int
be_perf_test_end_test(void *ctx)
{
    struct be_ctx *bectx;
    struct be_perf_test_args *targs = ctx;

    bectx = targs->bectx;

    return (*targs->reset_be)(bectx);
}

int
be_test_perf(struct be_ctx *bectx, const struct be_params *bep,
             int (*reset_be)(struct be_ctx *))
{
    int ret;
    struct be_perf_test_args args;
    struct perf_test_ctx *tctx;
    unsigned n;

    if (set_signal_handler(SIGINT, &int_handler) == -1
        || set_signal_handler(SIGTERM, &int_handler) == -1
        || set_signal_handler(SIGHUP, &pipe_handler) == -1
        || set_signal_handler(SIGPIPE, &pipe_handler) == -1) {
        ret = -errno;
        error(0, errno, "Couldn't set signal handler");
        return ret;
    }

    args.bectx = bectx;
    args.bep = bep;
    args.reset_be = reset_be;
    ret = init_perf_test(&tctx, &be_perf_test_ops, &args);
    if (ret != 0)
        goto err1;

    for (n = 64 * 1024; !quit && n < 1024 * 1024; n *= 2) {
        struct perf_test_info info;

        ret = do_perf_test(tctx, (void *)(uintptr_t)n, &info);
        if (ret != 0)
            goto err2;

        infomsgf("\nTest for n == %u: %.6f s\n",
                 n,
                 (double)info.tot_tm.tv_sec
                 + (double)info.tot_tm.tv_nsec / 1000000000.0);
    }

    end_perf_test(tctx);

    restore_default_handler(SIGINT);
    restore_default_handler(SIGTERM);

    return 0;

err2:
    end_perf_test(tctx);
err1:
    restore_default_handler(SIGINT);
    restore_default_handler(SIGTERM);
    return ret;
}

/* vi: set expandtab sw=4 ts=4: */
