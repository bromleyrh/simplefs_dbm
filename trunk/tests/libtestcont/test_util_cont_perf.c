/*
 * test_util_cont_perf.c
 */

#include "bitmap.h"
#include "test_util_cont.h"
#include "test_util_cont_util.h"
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

struct cont_perf_test_args {
    struct cont_ctx             *contctx;
    const struct cont_params    *contp;
    int                         (*reset_cont)(struct cont_ctx *);
    unsigned                    nops;
    unsigned                    n;
    unsigned                    nelem;
    unsigned                    epsilon;
    unsigned                    limit_lower;
    unsigned                    limit_upper;
};

#define EPSILON 8

#define NUM_PERF_TEST_OPS (4 * 1024 * 1024)

static int cont_perf_test_init_ctx(void **, void *);
static int cont_perf_test_destroy_ctx(void *);
static int cont_perf_test_prepare_test(void *, void *);
static int cont_perf_test_do_op(void *);
static int cont_perf_test_end_test(void *);

static const struct perf_test_ops cont_perf_test_ops = {
    .init_ctx       = cont_perf_test_init_ctx,
    .destroy_ctx    = cont_perf_test_destroy_ctx,
    .prepare_test   = cont_perf_test_prepare_test,
    .do_op          = cont_perf_test_do_op,
    .end_test       = cont_perf_test_end_test
};

static int
cont_perf_test_init_ctx(void **ctx, void *args)
{
    *ctx = args;

    return 0;
}

static int
cont_perf_test_destroy_ctx(void *ctx)
{
    (void)ctx;

    return 0;
}

static int
cont_perf_test_prepare_test(void *ctx, void *args)
{
    const struct cont_params *contp;
    int (*gen_key_fn)(int, int);
    int ret;
    struct cont_ctx *contctx;
    struct cont_perf_test_args *targs = (struct cont_perf_test_args *)ctx;
    unsigned n;

    contctx = targs->contctx;
    contp = targs->contp;

    gen_key_fn = contp->zero_keys ? &gen_key : &gen_key_no_zero;

    n = 0;
    while (n < (uintptr_t)args) {
        int key = (*gen_key_fn)(contp->max_key, params.out_of_range_period);

        ret = cont_insert(contctx, key, NULL, 1, 0, 0);
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
cont_perf_test_do_op(void *ctx)
{
    const struct cont_params *contp;
    enum {
        DELETE = 0,
        SEARCH = 1,
        INSERT = 2
    } op;
    int (*gen_key_fn)(int, int);
    int key;
    int lower_bound, upper_bound;
    int ret;
    struct cont_ctx *contctx;
    struct cont_perf_test_args *targs = (struct cont_perf_test_args *)ctx;

    contctx = targs->contctx;
    contp = targs->contp;

    gen_key_fn = contp->zero_keys ? &gen_key : &gen_key_no_zero;

    lower_bound = targs->nelem <= targs->limit_lower;
    upper_bound = targs->nelem >= targs->limit_upper;

    op = (lower_bound ? 1 : 0)
         + random()
           % ((lower_bound || upper_bound) ? 2 : 3);

    key = (*gen_key_fn)(contp->max_key, 0);

    switch (op) {
    case DELETE:
        ret = cont_delete(contctx, key, NULL, 1, 0, 0);
        if (ret != 0) {
            if (ret != -EADDRNOTAVAIL)
                return ret;
        } else
            --(targs->nelem);
        break;
    case SEARCH:
        ret = (contp->test_range_search && (random() % 2 == 0))
              ? cont_range_find(contctx, key, NULL, 0, 0)
              : cont_find(contctx, key, NULL, 0, 0);
        if (ret < 0)
            return ret;
        break;
    case INSERT:
        ret = cont_insert(contctx, key, NULL, 1, 0, 0);
        if (ret != 0) {
            if (ret != -EADDRINUSE)
                return ret;
        } else
            ++(targs->nelem);
        break;
    default:
        return -EIO;
    }

    fprintf(stderr, "\rn == %u: %u", targs->n, targs->nops);

    return (++(targs->nops) == NUM_PERF_TEST_OPS) ? 1 : 0;
}

static int
cont_perf_test_end_test(void *ctx)
{
    struct cont_ctx *contctx;
    struct cont_perf_test_args *targs = (struct cont_perf_test_args *)ctx;

    contctx = targs->contctx;

    return (*(targs->reset_cont))(contctx);
}

int
cont_test_perf(struct cont_ctx *contctx, const struct cont_params *contp,
               int (*reset_cont)(struct cont_ctx *))
{
    int ret;
    struct cont_perf_test_args args;
    struct perf_test_ctx *tctx;
    unsigned n;

    if ((set_signal_handler(SIGINT, &int_handler) == -1)
        || (set_signal_handler(SIGTERM, &int_handler) == -1)
        || (set_signal_handler(SIGHUP, &pipe_handler) == -1)
        || (set_signal_handler(SIGPIPE, &pipe_handler) == -1)) {
        ret = -errno;
        error(0, errno, "Couldn't set signal handler");
        return ret;
    }

    args.contctx = contctx;
    args.contp = contp;
    args.reset_cont = reset_cont;
    ret = init_perf_test(&tctx, &cont_perf_test_ops, &args);
    if (ret != 0)
        goto err1;

    for (n = (64 * 1024); !quit && (n < 1024 * 1024); n *= 2) {
        struct perf_test_info info;

        ret = do_perf_test(tctx, (void *)(uintptr_t)n, &info);
        if (ret != 0)
            goto err2;

        fprintf(stderr,
                "\nTest for n == %u: %.6f s\n",
                n,
                (double)(info.tot_tm.tv_sec)
                + (double)(info.tot_tm.tv_nsec) / 1000000000.0);
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
