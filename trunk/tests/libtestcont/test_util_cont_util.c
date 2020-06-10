/*
 * test_util_cont_util.c
 */

#include "test_util_cont.h"
#include "test_util_cont_util.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <bitmap.h>

#include <limits.h>
#include <stdlib.h>

struct params params = {
    .iter_test_period               = 1024,
    .iter_test_out_of_range_period  = 16 * 1024,
    .out_of_range_period            = 16 * 1024,
    .purge_factor                   = 8,
    .purge_interval                 = 8 * 1024 * 1024,
    .purge_period                   = 1024 * 1024,
    .sorted_test_period             = 4 * 1024
};

int
handle_usr_signals(struct cont_ctx *contctx1, struct cont_ctx *contctx2,
                   void *ctx)
{
    int ret;

    if (stats_requested) {
        stats_requested = 0;
        ret = (*(contctx1->cb.print_stats))(stderr, contctx1, 0);
        if (ret != 0)
            return ret;
    }

    if (verification_requested) {
        verification_requested = 0;
        ret = (*(contctx1->cb.verify_rand))(contctx1);
        if (ret != 0)
            return ret;
        if (contctx2 != NULL) {
            ret = (*(contctx1->cb.verify_cmp))(contctx1, contctx2, ctx);
            if (ret != 0)
                return ret;
        }
    }

    return 0;
}

int
check_insert_ratio(const struct cont_params *contp)
{
    if ((contp->insert_ratio < INT_MIN / 16)
        || (contp->insert_ratio > INT_MAX / 16)) {
        error(0, 0, "Invalid insertion ratio %d", contp->insert_ratio);
        return -EINVAL;
    }

    return 0;
}

int
check_max_key(const struct cont_params *contp)
{
    if (contp->max_key < 0) {
        error(0, 0, "Invalid maximum key value %d", contp->max_key);
        return -EINVAL;
    }

    return 0;
}

int
check_order_stats(const struct cont_ctx *contctx)
{
    if ((contctx->ops.select == NULL) || (contctx->ops.get_index == NULL)) {
        error(0, 0, "Container does not support order statistics operations");
        return -EINVAL;
    }

    return 0;
}

int
check_search_period(const struct cont_params *contp)
{
    if (contp->search_period <= 0) {
        error(0, 0, "Invalid search period %d", contp->search_period);
        return -EINVAL;
    }

    return 0;
}

int
gen_key(int max_key, int out_of_range_interval)
{
    if (((out_of_range_interval != 0) && !(random() % out_of_range_interval))
        || (max_key == INT_MAX))
        return random();

    return random() % (max_key+1);
}

int
gen_key_no_zero(int max_key, int out_of_range_interval)
{
    if ((out_of_range_interval != 0) && !(random() % out_of_range_interval))
        return random() % INT_MAX + 1;

    return random() % max_key + 1;
}

int
bitmap_select(struct bitmap_data *bmdata, int idx)
{
    int i;
    int ret = -1;
    unsigned tmp = 0;

    for (i = 0; i <= idx; i++) {
        if (bitmap_find_next_set(bmdata->bitmap, bmdata->bitmap_len, tmp, &tmp,
                                 1) == 0)
            break;
        if (i == idx) {
            ret = (int)tmp;
            break;
        }
        if (++tmp == bmdata->size)
            break;
    }

    return ret;
}

int
bitmap_get_index(struct bitmap_data *bmdata, int key)
{
    int found = 0;
    int i;
    unsigned tmp = 0;

    for (i = 0;; i++) {
        if (bitmap_find_next_set(bmdata->bitmap, bmdata->bitmap_len, tmp, &tmp,
                                 1) == 0)
            break;
        if ((int)tmp == key) {
            found = 1;
            break;
        }
        if (++tmp == bmdata->size)
            break;
    }

    return found ? i : -1;
}

int
auto_test_insert(struct cont_ctx *contctx, int key, int replace, int use_cont,
                 int use_bitmap, int nonexistent_allowed, int repeat_allowed,
                 int confirm)
{
    int fault = 0;
    int ret;

    if (use_cont) {
        ret = replace
              ? cont_replace(contctx, key, NULL, nonexistent_allowed, 0, 1)
              : cont_insert(contctx, key, NULL, repeat_allowed, 0, 1);
        if (ret != 0)
            return ret;
        fault = (fault_test == NULL) ? 0 : (*fault_test == 2);
        if (confirm) {
            ret = cont_find(contctx, key, NULL, 0, 1);
            if (ret == 0) {
                error(0, 0, "%s confirmation failed",
                      replace ? "Replacement" : "Insertion");
                return -EIO;
            }
            if (ret != 1) {
                error(0, -ret, "Error looking up in container");
                return ret;
            }
        }
    }

    if (use_bitmap && !replace) {
        struct bitmap_data *bmdata = (struct bitmap_data *)(contctx->bmdata);

        if (fault && (bitmap_get(bmdata->bitmap, key) == 0)) {
            error(0, 0, "Detectable %s fault generated",
                  replace ? "replacement" : "insertion");
            error(0, 0, "Verification before further operations should fail");
            cont_bitmap_set(contctx, key, 1, 0);
            return 2;
        }
        cont_bitmap_set(contctx, key, 1, !use_cont);
    }

    return 0;
}

int
auto_test_delete(struct cont_ctx *contctx, int key, int use_cont,
                 int use_bitmap, int repeat_allowed, int confirm)
{
    int fault = 0;
    int ret;
    struct bitmap_data *bmdata = (struct bitmap_data *)(contctx->bmdata);

    if (use_cont) {
        ret = cont_delete(contctx, key, NULL, repeat_allowed, 0, 1);
        if (ret != 0)
            return ret;
        fault = (fault_test == NULL) ? 0 : (*fault_test == 2);
        if (confirm) {
            ret = cont_find(contctx, key, NULL, 0, 1);
            if (ret == 1) {
                error(0, 0, "Deletion confirmation failed");
                return -EIO;
            }
            if (ret != 0) {
                error(0, -ret, "Error looking up in container");
                return ret;
            }
        }
    }

    if (use_bitmap && (key < (int)(bmdata->size))) {
        if (fault && (bitmap_get(bmdata->bitmap, key) == 1)) {
            error(0, 0, "Detectable deletion fault generated");
            error(0, 0, "Verification before further operations should fail");
            cont_bitmap_set(contctx, key, 0, 0);
            return 2;
        }
        cont_bitmap_set(contctx, key, 0, !use_cont);
    }

    return 0;
}

int
auto_test_delete_from(struct cont_ctx *contctx, int node, int *key,
                      int use_cont, int use_bitmap, int repeat_allowed,
                      int confirm)
{
    int fault = 0;
    int ret;
    struct bitmap_data *bmdata = (struct bitmap_data *)(contctx->bmdata);

    if (use_cont) {
        ret = cont_delete_from(contctx, node, key, repeat_allowed, 0, 1);
        if ((ret != 0) || (*key == -1))
            return ret;
        fault = (fault_test == NULL) ? 0 : (*fault_test == 2);
        if (confirm) {
            ret = cont_find(contctx, *key, NULL, 0, 1);
            if (ret == 1) {
                error(0, 0, "Deletion confirmation failed");
                return -EIO;
            }
            if (ret != 0) {
                error(0, -ret, "Error looking up in container");
                return ret;
            }
        }
    }

    if (use_bitmap && (*key < (int)(bmdata->size))) {
        if (fault && (bitmap_get(bmdata->bitmap, *key) == 1)) {
            error(0, 0, "Detectable deletion fault generated");
            error(0, 0, "Verification before further operations should fail");
            cont_bitmap_set(contctx, *key, 0, 0);
            return 2;
        }
        cont_bitmap_set(contctx, *key, 0, !use_cont);
    }

    return 0;
}

int
auto_test_search(struct cont_ctx *contctx, int key, int use_cont,
                 int use_bitmap)
{
    int fault = 0;
    int ret = 0;

    if (use_cont) {
        ret = cont_find(contctx, key, NULL, 0, 1);
        if (ret < 0)
            return ret;
        fault = (fault_test == NULL) ? 0 : (*fault_test == 2);
    }

    if (use_bitmap) {
        struct bitmap_data *bmdata = (struct bitmap_data *)(contctx->bmdata);

        int tmp = (key < (int)(bmdata->size))
                  ? bitmap_get(bmdata->bitmap, key) : 0;

        if (fault && (tmp == 1)) {
            error(0, 0, "Detectable search fault generated");
            error(0, 0, "Test error should follow");
        }

        if (use_cont && (tmp != ret)) {
            error(0, 0, "Bitmap and container differ at %d (%d vs. %d)", key,
                  !ret, ret);
            return -EIO;
        }
        if (!use_cont)
            ++(contctx->stats.num_ops);
    }

    return 0;
}

int
auto_test_range_search(struct cont_ctx *contctx, int key, int use_cont,
                       int use_bitmap)
{
    int fault = 0;
    int ret = 0;

    if (use_cont) {
        ret = cont_range_find(contctx, key, NULL, 0, 1);
        if (ret < 0)
            return ret;
        fault = (fault_test == NULL) ? 0 : (*fault_test == 2);
    }

    if (use_bitmap) {
        struct bitmap_data *bmdata = (struct bitmap_data *)(contctx->bmdata);

        int tmp = (key < (int)(bmdata->size))
                  ? bitmap_get(bmdata->bitmap, key) : 0;

        if (fault && (tmp == 1)) {
            error(0, 0, "Detectable search fault generated");
            error(0, 0, "Test error should follow");
        }

        if (use_cont && (tmp != ret)) {
            error(0, 0, "Bitmap and container differ at %d (%d vs. %d)", key,
                  !ret, ret);
            return -EIO;
        }
        if (!use_cont)
            ++(contctx->stats.num_ops);
    }

    return 0;
}

int
auto_test_select(struct cont_ctx *contctx, int idx, int use_cont,
                 int use_bitmap)
{
    int fault = 0;
    int ret = 0;

    if (use_cont) {
        int res;

        ret = cont_select(contctx, idx, &res, 0, 1);
        if (ret < 0)
            return ret;
        ret = (ret == 0) ? -1 : res;
        fault = (fault_test == NULL) ? 0 : (*fault_test == 2);
    }

    if (use_bitmap) {
        struct bitmap_data *bmdata = (struct bitmap_data *)(contctx->bmdata);

        int tmp = (idx < (int)(bmdata->size)) ? bitmap_select(bmdata, idx) : -1;

        if (fault && (tmp != -1)) {
            error(0, 0, "Detectable select fault generated");
            error(0, 0, "Test error should follow");
        }

        if (use_cont && (tmp != ret)) {
            error(0, 0, "Bitmap and container differ at index %d (%d vs. %d)",
                  idx, tmp, ret);
            return -EIO;
        }
        if (!use_cont)
            ++(contctx->stats.num_ops);
    }

    return 0;
}

int
auto_test_get_index(struct cont_ctx *contctx, int key, int use_cont,
                    int use_bitmap)
{
    int fault = 0;
    int ret = 0;

    if (use_cont) {
        int res;

        ret = cont_get_index(contctx, key, &res, 0, 1);
        if (ret < 0)
            return ret;
        ret = (ret == 0) ? -1 : res;
        fault = (fault_test == NULL) ? 0 : (*fault_test == 2);
    }

    if (use_bitmap) {
        struct bitmap_data *bmdata = (struct bitmap_data *)(contctx->bmdata);

        int tmp = (key < (int)(bmdata->size))
                  ? bitmap_get_index(bmdata, key) : -1;

        if (fault && (tmp != -1)) {
            error(0, 0, "Detectable get-index fault generated");
            error(0, 0, "Test error should follow");
        }

        if (use_cont && (tmp != ret)) {
            error(0, 0, "Bitmap and container differ in index of key %d (%d "
                  "vs. %d)", key, tmp, ret);
            return -EIO;
        }
        if (!use_cont)
            ++(contctx->stats.num_ops);
    }

    return 0;
}

int
auto_test_walk(struct cont_ctx *contctx, int key, int use_cont, int use_bitmap)
{
    int ret = 0;

    (void)use_bitmap;

    if (use_cont) {
        int tmp;

        ret = (*(contctx->cb.init_walk_data))(contctx, contctx->wctx);
        if (ret != 0)
            return ret;

        ret = cont_walk(contctx, key, contctx->wfn, contctx->wctx, 0, 1);

        tmp = (*(contctx->cb.free_walk_data))(contctx, contctx->wctx, ret != 0);
        if (ret == 0)
            ret = tmp;
    }

    return ret;
}

/* vi: set expandtab sw=4 ts=4: */