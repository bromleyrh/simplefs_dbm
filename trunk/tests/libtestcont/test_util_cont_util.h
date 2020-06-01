/*
 * test_util_cont_util.h
 */

#ifndef _TEST_UTIL_CONT_UTIL_H
#define _TEST_UTIL_CONT_UTIL_H

#include "test_util_cont.h"
#include "test_util_cont_config.h"

#include <test_util.h>

#include <errno.h>
#include <stdio.h>

#include <sys/time.h>

extern struct params params;

#define ERROR_FATAL(err) \
    (((err) < 0) && ((err) != -ENOSPC) && (((err) != -ENOMEM) || !(*mem_test)))

#define NUM_OPS(contctx) \
    ((contctx)->stats.num_ops - (contctx)->stats.num_ops_start)

#define VERBOSE_LOG(f, format, ...) \
    do { \
        if ((verbose_debug != NULL) && *verbose_debug) \
            fprintf(f, format, ##__VA_ARGS__); \
    } while (0)

static inline void
refresh_stat_output(struct cont_ctx *contctx)
{
    static struct timeval last_print_time = {.tv_sec = 0, .tv_usec = 0};
    struct timeval curr;

    if ((gettimeofday(&curr, NULL) == 0)
        && ((curr.tv_sec - last_print_time.tv_sec
             + 0.000001 * (curr.tv_usec-last_print_time.tv_usec)) >= 1.0)) {
        clrscr(stderr);
        (*(contctx->cb.print_stats))(stderr, contctx, 0);
        last_print_time = curr;
    }
}

int handle_usr_signals(struct cont_ctx *contctx1, struct cont_ctx *contctx2,
                       void *ctx);

int check_insert_ratio(const struct cont_params *contp);
int check_max_key(const struct cont_params *contp);
int check_order_stats(const struct cont_ctx *contp);
int check_search_period(const struct cont_params *contp);

int gen_key(int max_key, int out_of_range_interval);
int gen_key_no_zero(int max_key, int out_of_range_interval);

int bitmap_select(struct bitmap_data *bmdata, int idx);
int bitmap_get_index(struct bitmap_data *bmdata, int key);

int auto_test_insert(struct cont_ctx *contctx, int key, int replace,
                     int use_cont, int use_bitmap, int nonexistent_allowed,
                     int repeat_allowed, int confirm);
int auto_test_delete(struct cont_ctx *contctx, int key, int use_cont,
                     int use_bitmap, int repeat_allowed, int confirm);
int auto_test_delete_from(struct cont_ctx *contctx, int node, int *key,
                          int use_cont, int use_bitmap, int repeat_allowed,
                          int confirm);
int auto_test_search(struct cont_ctx *contctx, int key, int use_cont,
                     int use_bitmap);
int auto_test_range_search(struct cont_ctx *contctx, int key, int use_cont,
                           int use_bitmap);
int auto_test_select(struct cont_ctx *contctx, int idx, int use_cont,
                     int use_bitmap);
int auto_test_get_index(struct cont_ctx *contctx, int key, int use_cont,
                        int use_bitmap);
int auto_test_walk(struct cont_ctx *contctx, int key, int use_cont,
                   int use_bitmap);

#endif

/* vi: set expandtab sw=4 ts=4: */
