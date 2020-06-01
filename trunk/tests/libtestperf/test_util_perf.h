/*
 * test_util_perf.h
 */

#ifndef _TEST_UTIL_PERF_H
#define _TEST_UTIL_PERF_H

#include "test_util_perf_common.h"

#include <sys/time.h>

struct perf_test_ctx;

struct perf_test_ops {
    int (*init_ctx)(void **ctx, void *args);
    int (*destroy_ctx)(void *ctx);
    int (*prepare_test)(void *ctx, void *args);
    int (*do_op)(void *ctx);
    int (*end_test)(void *ctx);
};

struct perf_test_info {
    struct timespec start_tm;
    struct timespec end_tm;
    struct timespec tot_tm;
};

LIBTESTPERF_EXPORTED int init_perf_test(struct perf_test_ctx **ctx,
                                        const struct perf_test_ops *ops,
                                        void *args);
LIBTESTPERF_EXPORTED int end_perf_test(struct perf_test_ctx *ctx);

LIBTESTPERF_EXPORTED int do_perf_test(struct perf_test_ctx *ctx, void *args,
                                      struct perf_test_info *info);

#endif

/* vi: set expandtab sw=4 ts=4: */
