/*
 * test_util_cont_ordered.c
 */

#include "test_util_cont.h"
#include "test_util_cont_ordered.h"
#include "util_test_common.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <bitmap.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#include <sys/mman.h>

static int check_increasing(int *, int);

#define DEF_WALK_FN(nm) \
    static walk_fn_ordered_t walk_ ## nm; \
    walk_fn_ordered_t *nm = &walk_ ## nm

DEF_WALK_FN(fn1);
DEF_WALK_FN(fn2);
DEF_WALK_FN(fn3);

static int
check_increasing(int *prev, int curr)
{
    static int previous = -1;

    if (!prev)
        prev = &previous;

    if (curr <= *prev) {
        error(0, 0, "curr <= prev during walk (%d <= %d)", curr, *prev);
        return -1;
    }

    *prev = curr;

    return 0;
}

static int
walk_fn1(const void *kv, void *ctx)
{
    int curr;
    struct fn1_ctx *data = (struct fn1_ctx *)ctx;

    curr = get_short_key((const int *)kv, data->key_size);

    ++(data->keys_found);
    return (check_increasing(&data->prevkey, curr) == 0) ? 0 : -EIO;
}

static int
walk_fn2(const void *kv, void *ctx)
{
    int curr;
    struct fn2_ctx *data = (struct fn2_ctx *)ctx;

    curr = get_short_key((const int *)kv, data->key_size);

    ++(data->keys_found);
    if (check_increasing(&data->prevkey, curr) == -1)
        return -EIO;

    printf("%d\n", curr);

    /* test walk resume */
    return (data->walk_resume_test && ((data->keys_found % 10) == 0))
           ? data->walk_resume_retval : 0;
}

static int
walk_fn3(const void *kv, void *ctx)
{
    char output[64];
    int curr;
    struct fn3_ctx *data = (struct fn3_ctx *)ctx;

    curr = get_short_key((const int *)kv, data->key_size);

    ++(data->keys_found);
    if (check_increasing(&data->prevkey, curr) == -1) {
        if (data->keys_found > 1)
            fputc('\n', stderr);
        return -EIO;
    }

    if ((bitmap_find_next_set(data->bmdata->bitmap, data->bmdata->bitmap_len,
                              data->bitmap_pos, (unsigned *)(&data->bitmap_pos),
                              1) == 0)
        || (curr != data->bitmap_pos)) {
        snprintf(output, sizeof(output),
                 "Bitmap (%6d) and container (%6d) differ\n",
                 data->bitmap_pos, curr);
        if (data->keys_found > 1)
            fputc('\n', stderr);
        fputs(output, stderr);
        if (data->checklog != NULL)
            fputs(output, data->checklog);
        return -EIO;
    }

    snprintf(output, sizeof(output), "Bitmap and container agree up to %6d",
             data->bitmap_pos);
    fputc('\r', stderr);
    fputs(output, stderr);
    if (data->checklog != NULL) {
        fputs(output, data->checklog);
        fputc('\n', data->checklog);
    }

    ++(data->bitmap_pos);

    /* test walk resume */
    return (data->walk_resume_test && ((data->keys_found % 10) == 0))
           ? data->walk_resume_retval : 0;
}

int
verify_insertion_ordered(struct cont_ctx *contctx)
{
    int ret;
    struct cont_ctx_ordered *ctx = (struct cont_ctx_ordered *)(contctx->ctx);
    struct cont_stats *cstats = &contctx->stats;
    void *cont = (struct avl_tree *)(contctx->cont);
    void *wctx = NULL;

    struct fn1_ctx data = {
        .key_size   = contctx->key_size,
        .prevkey    = -1,
        .keys_found = 0
    };

    ret = (*(ctx->test_walk))(cont, NULL, fn1, &data, &wctx);
    if (ret != 0) {
        error(0, -ret, "Error walking container");
        return ret;
    }

    if (ctx->test_stats != NULL) {
        struct cont_stats_ordered stats;

        ret = (*(ctx->test_stats))(cont, &stats);
        if (ret != 0) {
            error(0, -ret, "Error getting container stats");
            return ret;
        }

        if (stats.num_keys != cstats->num_keys) {
            error(0, 0, "num_keys in container (%u) != number of keys counted "
                  "(%" PRIu32 ")", stats.num_keys, cstats->num_keys);
            return -EIO;
        }

        fprintf(stderr, "%u keys found, %u keys inserted\n", data.keys_found,
                stats.num_keys);

        if (data.keys_found != stats.num_keys) {
            error(0, 0, "Number of keys returned by walk (%u) != num_keys in "
                  "container (%u)", data.keys_found, stats.num_keys);
            return -EIO;
        }
    } else {
        if (data.keys_found != cstats->num_keys) {
            error(0, 0, "Number of keys returned by walk (%u) != number of "
                  "keys counted (%" PRIu32 ")", data.keys_found,
                  cstats->num_keys);
            return -EIO;
        }
    }

    return 0;
}

int
verify_rand_ordered(struct cont_ctx *contctx)
{
    int ret;
    struct bitmap_data *bmdata;
    struct cont_ctx_ordered *ctx = (struct cont_ctx_ordered *)(contctx->ctx);
    struct fn3_ctx data;
    void *wctx = NULL;

    bmdata = (struct bitmap_data *)(contctx->bmdata);

    data.checklog = open_log_file(1);
    if (data.checklog == NULL)
        return -errno;

    if (mprotect(bmdata->bitmap, bmdata->bitmap_len * sizeof(unsigned),
                 PROT_READ) == -1) {
        ret = -errno;
        error(0, errno, "Couldn't set memory protection");
        goto end1;
    }

    data.bmdata = bmdata;
    data.bitmap_pos = 0;
    data.key_size = contctx->key_size;
    data.keys_found = 0;
    data.prevkey = -1;
    data.walk_resume_test = 1;
    data.walk_resume_retval = ctx->walk_resume_retval;

    while ((ret = (*(ctx->test_walk))(contctx->cont, NULL, fn3, &data, &wctx))
           == 1)
        ;
    if (ret != 0) {
        error(0, -ret, "Error walking container");
        goto end2;
    }
    if (data.keys_found > 0)
        fputc('\n', stderr);

    if (bitmap_find_next_set(data.bmdata->bitmap, data.bmdata->bitmap_len,
                             data.bitmap_pos, (unsigned *)(&data.bitmap_pos), 1)
        != 0) {
        fputs("Bitmap and container differ\n", stderr);
        fputs("Bitmap and container differ\n", data.checklog);
        ret = -EIO;
    }

end2:
    mprotect(bmdata->bitmap, bmdata->bitmap_len * sizeof(unsigned),
             PROT_READ | PROT_WRITE);
end1:
    close_log_file(data.checklog);
    return ret;
}

/* vi: set expandtab sw=4 ts=4: */
