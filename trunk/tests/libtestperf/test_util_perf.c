/*
 * test_util_perf.c
 */

#include "test_util_perf.h"
#include "util.h"

#include <time_ext.h>

#define ASSERT_MACROS
#include "common.h"
#undef ASSERT_MACROS

#include <stddef.h>
#include <stdlib.h>

#ifdef HAVE_CLOCK_GETTIME
  #ifdef CLOCK_MONOTONIC_RAW
    #define CLKID CLOCK_MONOTONIC_RAW
  #else
    #define CLKID CLOCK_REALTIME
  #endif
#else
  #define CLKID CLOCK_REALTIME
#endif

struct perf_test_ctx {
    void                        *ctx;
    const struct perf_test_ops  *ops;
};

int
init_perf_test(struct perf_test_ctx **ctx, const struct perf_test_ops *ops,
               void *args)
{
    int err;
    struct perf_test_ctx *ret;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return MINUS_ERRNO;

    err = (*(ops->init_ctx))(&ret->ctx, args);
    if (err) {
        free(ret);
        return err;
    }

    ret->ops = ops;

    *ctx = ret;
    return 0;
}

int
end_perf_test(struct perf_test_ctx *ctx)
{
    int err;

    err = (*(ctx->ops->destroy_ctx))(ctx->ctx);
    if (err)
        return err;

    free(ctx);

    return 0;
}

int
do_perf_test(struct perf_test_ctx *ctx, void *args, struct perf_test_info *info)
{
    int ret;
    struct perf_test_info retinfo;

    ret = (*(ctx->ops->prepare_test))(ctx->ctx, args);
    if (ret != 0)
        return ret;

    ret = gettime(CLKID, &retinfo.start_tm);
    if (ret != 0)
        goto err;
    for (;;) {
        ret = (*(ctx->ops->do_op))(ctx->ctx);
        if (ret != 0) {
            if (ret == 1)
                break;
            goto err;
        }
    }
    ret = gettime(CLKID, &retinfo.end_tm);
    if (ret != 0)
        goto err;

    ret = (*(ctx->ops->end_test))(ctx->ctx);
    if (ret != 0)
        return ret;

    timespec_diff(&retinfo.end_tm, &retinfo.start_tm, &retinfo.tot_tm);

    *info = retinfo;
    return 0;

err:
    (*(ctx->ops->end_test))(ctx->ctx);
    return ret;
}

/* vi: set expandtab sw=4 ts=4: */
