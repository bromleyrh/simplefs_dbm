/*
 * test_util_back_end_ordered.c
 */

#include "test_util_back_end.h"
#include "test_util_back_end_ordered.h"
#include "util_test_common.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <bitmap.h>
#include <strings_ext.h>

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
            infochr('\n');
        return -EIO;
    }

    if ((bitmap_find_next_set(data->bmdata->bitmap, data->bmdata->bitmap_len,
                              data->bitmap_pos, (unsigned *)(&data->bitmap_pos),
                              1) == 0)
        || (curr != data->bitmap_pos)) {
        fillbuf(output, "Bitmap (%6d) and back end (%6d) differ\n",
                data->bitmap_pos, curr);
        if (data->keys_found > 1)
            infochr('\n');
        infomsg(output);
        if (data->checklog != NULL)
            fputs(output, data->checklog);
        return -EIO;
    }

    fillbuf(output, "Bitmap and back end agree up to %6d", data->bitmap_pos);
    infochr('\r');
    infomsg(output);
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
verify_insertion_ordered(struct be_ctx *bectx)
{
    int ret;
    struct be_ctx_ordered *ctx = (struct be_ctx_ordered *)(bectx->ctx);
    struct be_stats *cstats = &bectx->stats;
    void *be = (struct avl_tree *)(bectx->be);
    void *wctx = NULL;

    struct fn1_ctx data = {
        .key_size   = bectx->key_size,
        .prevkey    = -1,
        .keys_found = 0
    };

    ret = (*(ctx->test_walk))(be, NULL, fn1, &data, &wctx);
    if (ret != 0) {
        error(0, -ret, "Error walking back end");
        return ret;
    }

    if (ctx->test_stats != NULL) {
        struct be_stats_ordered stats;

        ret = (*(ctx->test_stats))(be, &stats);
        if (ret != 0) {
            error(0, -ret, "Error getting back end stats");
            return ret;
        }

        if (stats.num_keys != cstats->num_keys) {
            error(0, 0, "num_keys in back end (%u) != number of keys counted "
                  "(%" PRIu32 ")", stats.num_keys, cstats->num_keys);
            return -EIO;
        }

        infomsgf("%u keys found, %u keys inserted\n", data.keys_found,
                 stats.num_keys);

        if (data.keys_found != stats.num_keys) {
            error(0, 0, "Number of keys returned by walk (%u) != num_keys in "
                  "back end (%u)", data.keys_found, stats.num_keys);
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
verify_rand_ordered(struct be_ctx *bectx)
{
    int ret;
    struct be_ctx_ordered *ctx = (struct be_ctx_ordered *)(bectx->ctx);
    struct bitmap_data *bmdata;
    struct fn3_ctx data;
    void *wctx = NULL;

    bmdata = (struct bitmap_data *)(bectx->bmdata);

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
    data.key_size = bectx->key_size;
    data.keys_found = 0;
    data.prevkey = -1;
    data.walk_resume_test = 1;
    data.walk_resume_retval = ctx->walk_resume_retval;

    while ((ret = (*(ctx->test_walk))(bectx->be, NULL, fn3, &data, &wctx))
           == 1)
        ;
    if (ret != 0) {
        error(0, -ret, "Error walking back end");
        goto end2;
    }
    if (data.keys_found > 0)
        infochr('\n');

    if (bitmap_find_next_set(data.bmdata->bitmap, data.bmdata->bitmap_len,
                             data.bitmap_pos, (unsigned *)(&data.bitmap_pos), 1)
        != 0) {
        infomsg("Bitmap and back end differ\n");
        fputs("Bitmap and back end differ\n", data.checklog);
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
