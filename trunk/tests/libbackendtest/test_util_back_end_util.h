/*
 * test_util_back_end_util.h
 */

#ifndef _TEST_UTIL_BACK_END_UTIL_H
#define _TEST_UTIL_BACK_END_UTIL_H

#include "test_util_back_end.h"
#include "test_util_back_end_config.h"

#include <test_util.h>

#include <errno.h>
#include <stdio.h>

#include <sys/time.h>

extern struct params params;

#define ERROR_FATAL(err) \
    (((err) < 0) && ((err) != -ENOSPC) && (((err) != -ENOMEM) || !*mem_test))

#define NUM_OPS(bectx) ((bectx)->stats.num_ops - (bectx)->stats.num_ops_start)

#define VERBOSE_LOG(f, format, ...) \
    do { \
        if ((verbose_debug != NULL) && *verbose_debug) \
            fprintf(f, format, ##__VA_ARGS__); \
    } while (0)

static inline void
refresh_stat_output(struct be_ctx *bectx)
{
    static struct timeval last_print_time = {.tv_sec = 0, .tv_usec = 0};
    struct timeval curr;

    if ((gettimeofday(&curr, NULL) == 0)
        && ((curr.tv_sec - last_print_time.tv_sec
             + 0.000001 * (curr.tv_usec-last_print_time.tv_usec)) >= 1.0)) {
        clrscr(stderr);
        (*bectx->cb.print_stats)(stderr, bectx, 0);
        last_print_time = curr;
    }
}

int handle_usr_signals(struct be_ctx *bectx1, struct be_ctx *bectx2, void *ctx);

int check_insert_ratio(const struct be_params *bep);
int check_max_key(const struct be_params *bep);
int check_order_stats(const struct be_ctx *bep);
int check_search_period(const struct be_params *bep);

int gen_key(int max_key, int out_of_range_interval);
int gen_key_no_zero(int max_key, int out_of_range_interval);

int bitmap_select(struct bitmap_data *bmdata, int idx);
int bitmap_get_index(struct bitmap_data *bmdata, int key);

int auto_test_insert(struct be_ctx *bectx, int key, int replace, int use_be,
                     int use_bitmap, int nonexistent_allowed,
                     int repeat_allowed, int confirm);
int auto_test_delete(struct be_ctx *bectx, int key, int use_be, int use_bitmap,
                     int repeat_allowed, int confirm);
int auto_test_delete_from(struct be_ctx *bectx, int node, int *key, int use_be,
                          int use_bitmap, int repeat_allowed, int confirm);
int auto_test_search(struct be_ctx *bectx, int key, int use_be, int use_bitmap);
int auto_test_range_search(struct be_ctx *bectx, int key, int use_be,
                           int use_bitmap);
int auto_test_select(struct be_ctx *bectx, int idx, int use_be, int use_bitmap);
int auto_test_get_index(struct be_ctx *bectx, int key, int use_be,
                        int use_bitmap);
int auto_test_walk(struct be_ctx *bectx, int key, int use_be, int use_bitmap);
int auto_test_trans_new(struct be_ctx *bectx, int use_be, int use_bitmap);
int auto_test_trans_abort(struct be_ctx *bectx, int use_be, int use_bitmap);
int auto_test_trans_commit(struct be_ctx *bectx, int use_be, int use_bitmap);

#endif

/* vi: set expandtab sw=4 ts=4: */
