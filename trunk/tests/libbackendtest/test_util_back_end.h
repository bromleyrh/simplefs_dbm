/*
 * test_util_back_end.h
 */

#ifndef _TEST_UTIL_BACK_END_H
#define _TEST_UTIL_BACK_END_H

#include "test_util_back_end_common.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define CONFIG_PATH_ENV "BACKENDTEST_CONFIG_PATH"

#define DEFAULT_CONFIG_PATH "backendtest_config.json"

struct be_test_opts {
    struct be_params    *bep;
    int                 order_stats;
    int                 (*parse_test_opt)(int, void *);
    void                *test_opts;
};

struct be_params {
    int         insert_ratio;
    int         key_size;
    int         max_key;
    uint64_t    num_ops;
    int         search_period;
    int         verbose_stats;
    int         verification_period;
    unsigned    confirm:1;
    unsigned    delete_from_root:1;
    unsigned    dump:1;
    unsigned    empty_on_fill:1;
    unsigned    test_order_stats:1;
    unsigned    test_range_search:1;
    unsigned    test_replace:1;
    unsigned    test_iter:2;
    unsigned    test_walk:1;
    unsigned    use_bitmap:1;
    unsigned    use_be:1;
    unsigned    verify:1;
    unsigned    verify_after_search:1;
    unsigned    zero_keys:1;
};

struct be_ops {
    int (*insert)(void *be, void *key);
    int (*replace)(void *be, void *key);
    int (*search)(void *be, void *key, void *res);
    int (*range_search)(void *be, void *key, void *res);
    int (*select)(void *be, int idx, void *res);
    int (*get_index)(void *be, void *key, int *idx);
    int (*delete)(void *be, void *key);
    int (*delete_from)(void *be, int node, void *res);
    int (*walk)(void *be, void *startkey, int (*fn)(const void *, void *),
                void *ctx);
    int (*iter_new)(void **iter, void *be);
    int (*iter_free)(void *iter);
    int (*iter_get)(void *iter, void *ret);
    int (*iter_prev)(void *iter);
    int (*iter_next)(void *iter);
    int (*iter_search)(void *iter, const void *key);
    int (*iter_select)(void *iter, int idx);
    int (*dump)(FILE *f, void *be);
};

struct be_ctx;
struct be_cb {
    int (*init_walk_data)(struct be_ctx *bectx, void *ctx);
    int (*free_walk_data)(struct be_ctx *bectx, void *ctx, int error);
    int (*verify_insertion)(struct be_ctx *bectx);
    int (*verify_rand)(struct be_ctx *bectx);
    int (*verify_cmp)(struct be_ctx *bectx1, struct be_ctx *bectx2, void *ctx);
    int (*print_stats)(FILE *f, struct be_ctx *bectx, int times);
    int (*end_test)(struct be_ctx *bectx);
};

#define SET_STD_OPS_NO_DUMP(bectx, prefix) \
    (bectx).ops.insert = (typeof((bectx).ops.insert))&(prefix ## _insert); \
    (bectx).ops.search = (typeof((bectx).ops.search))&(prefix ## _search); \
    (bectx).ops.select = NULL; \
    (bectx).ops.get_index = NULL; \
    (bectx).ops.delete = (typeof((bectx).ops.delete))&(prefix ## _delete); \
    (bectx).ops.dump = NULL

#define SET_STD_OPS(bectx, prefix) \
    (bectx).ops.insert = (typeof((bectx).ops.insert))&(prefix ## _insert); \
    (bectx).ops.search = (typeof((bectx).ops.search))&(prefix ## _search); \
    (bectx).ops.select = NULL; \
    (bectx).ops.get_index = NULL; \
    (bectx).ops.delete = (typeof((bectx).ops.delete))&(prefix ## _delete); \
    (bectx).ops.dump = (typeof((bectx).ops.dump))&(prefix ## _dump)

#define SET_ALL_OPS(bectx, prefix) \
    SET_STD_OPS(bectx, prefix); \
    (bectx).ops.select = (typeof((bectx).ops.select))&(prefix ## _select); \
    (bectx).ops.get_index \
        = (typeof((bectx).ops.get_index))&(prefix ## _get_index)

#define SET_REPLACE_OP(bectx, prefix) \
    (bectx).ops.replace = (typeof((bectx).ops.replace))&(prefix ## _replace)

#define SET_DELETE_FROM_OP(bectx, prefix) \
    (bectx).ops.delete_from \
        = (typeof((bectx).ops.delete_from))&(prefix ## _delete_from)

#define SET_RANGE_SEARCH_OP(bectx, prefix) \
    (bectx).ops.range_search \
        = (typeof((bectx).ops.range_search))&(prefix ## _range_search)

#define SET_WALK_OP(bectx, prefix) \
    (bectx).ops.walk = (typeof((bectx).ops.walk))&(prefix ## _walk)

#define SET_STD_ITER_OPS_NO_PREV(bectx, prefix) \
    (bectx).ops.iter_new \
        = (typeof((bectx).ops.iter_new))&(prefix ## _iter_new); \
    (bectx).ops.iter_free \
        = (typeof((bectx).ops.iter_free))&(prefix ## _iter_free); \
    (bectx).ops.iter_get \
        = (typeof((bectx).ops.iter_get))&(prefix ## _iter_get); \
    (bectx).ops.iter_prev = NULL; \
    (bectx).ops.iter_next \
        = (typeof((bectx).ops.iter_next))&(prefix ## _iter_next); \
    (bectx).ops.iter_search \
        = (typeof((bectx).ops.iter_search))&(prefix ## _iter_search); \
    (bectx).ops.iter_select = NULL

#define SET_STD_ITER_OPS(bectx, prefix) \
    SET_STD_ITER_OPS_NO_PREV(bectx, prefix); \
    (bectx).ops.iter_prev \
        = (typeof((bectx).ops.iter_prev))&(prefix ## _iter_prev)

#define SET_ALL_ITER_OPS(bectx, prefix) \
    SET_STD_ITER_OPS(bectx, prefix); \
    (bectx).ops.iter_select \
        = (typeof((bectx).ops.iter_select))&(prefix ## _iter_select)

struct be_stats {
    uint64_t num_gen;
    uint64_t num_ops;
    uint64_t num_ops_start;
    uint64_t num_ops_out_of_range;
    uint64_t repeat_inserts;
    uint64_t invalid_replacements;
    uint64_t repeat_deletes;
    uint32_t num_keys;
};

struct be_ctx {
    void            *be;
    struct be_ops   ops;
    int             key_size;
    int             max_key;
    int             (*wfn)(const void *, void *);
    void            *wctx;
    struct be_cb    cb;
    struct be_stats stats;
    void            *bmdata;
    void            *ctx;
};

extern LIBBACKENDTEST_EXPORTED void (*term_handler)(int);

#define MAX_KEY_SIZE 4096

LIBBACKENDTEST_EXPORTED int parse_be_test_cmdline(int argc, char **argv,
                                                  const char *progusage,
                                                  const char *test_opt_str,
                                                  int (*parse_test_opt)(int,
                                                                        void *),
                                                  struct be_params *bep,
                                                  void *test_opts, int *seed,
                                                  int *enable_mtrace,
                                                  int *run_gdb, int *shell,
                                                  int order_stats);

LIBBACKENDTEST_EXPORTED void init_be_ctx(struct be_ctx *bectx, void *bmdata,
                                         int key_size, int max_key);

LIBBACKENDTEST_EXPORTED int *get_full_key(int key, int key_size, int *buf);
LIBBACKENDTEST_EXPORTED int get_short_key(const int *full_key, int key_size);

LIBBACKENDTEST_EXPORTED int int_key_cmp(const void *k1, const void *k2,
                                        void *ctx);

LIBBACKENDTEST_EXPORTED const char *int_key_to_str(const void *k, void *ctx);

LIBBACKENDTEST_EXPORTED void be_bitmap_set(struct be_ctx *bectx, int key,
                                           int val, int record_stats);

LIBBACKENDTEST_EXPORTED int be_insert(struct be_ctx *bectx, int key,
                                      int *result, int repeat_allowed,
                                      int verbose, int record_stats);
LIBBACKENDTEST_EXPORTED int be_replace(struct be_ctx *becx, int key,
                                       int *result, int nonexistent_allowed,
                                       int verbose, int record_stats);
LIBBACKENDTEST_EXPORTED int be_delete(struct be_ctx *bectx, int key,
                                      int *result, int repeat_allowed,
                                      int verbose, int record_stats);
LIBBACKENDTEST_EXPORTED int be_delete_from(struct be_ctx *bectx, int node,
                                           int *result, int repeat_allowed,
                                           int verbose, int record_stats);
LIBBACKENDTEST_EXPORTED int be_find(struct be_ctx *bectx, int key, int *result,
                                    int verbose, int record_stats);
LIBBACKENDTEST_EXPORTED int be_range_find(struct be_ctx *bectx, int key,
                                          int *result, int verbose,
                                          int record_stats);
LIBBACKENDTEST_EXPORTED int be_select(struct be_ctx *bectx, int idx,
                                      int *result, int verbose,
                                      int record_stats);
LIBBACKENDTEST_EXPORTED int be_get_index(struct be_ctx *bectx, int key,
                                         int *result, int verbose,
                                         int record_stats);
LIBBACKENDTEST_EXPORTED int be_walk(struct be_ctx *bectx, int startkey,
                                    int (*fn)(const void *, void *), void *ctx,
                                    int verbose, int record_stats);

LIBBACKENDTEST_EXPORTED int be_iter_new(struct be_ctx *bectx, void **result,
                                        int verbose, int record_stats);
LIBBACKENDTEST_EXPORTED int be_iter_free(struct be_ctx *bectx, void *iter,
                                         int verbose, int record_stats);
LIBBACKENDTEST_EXPORTED int be_iter_get(struct be_ctx *bectx, void *iter,
                                        int *result, int verbose,
                                        int record_stats);
LIBBACKENDTEST_EXPORTED int be_iter_prev(struct be_ctx *bectx, void *iter,
                                         int verbose, int record_stats);
LIBBACKENDTEST_EXPORTED int be_iter_next(struct be_ctx *bectx, void *iter,
                                         int verbose, int record_stats);
LIBBACKENDTEST_EXPORTED int be_iter_search(struct be_ctx *bectx, void *iter,
                                          int key, int verbose,
                                          int record_stats);
LIBBACKENDTEST_EXPORTED int be_iter_select(struct be_ctx *bectx, void *iter,
                                           int idx, int verbose,
                                           int record_stats);

LIBBACKENDTEST_EXPORTED int be_test_quick(struct be_ctx *bectx,
                                          const struct be_params *bep);
LIBBACKENDTEST_EXPORTED int be_test_insertion(struct be_ctx *bectx,
                                              const struct be_params *bep,
                                              FILE *log);
LIBBACKENDTEST_EXPORTED int be_test_rand_repeat(struct be_ctx *bectx,
                                                const struct be_params *bep,
                                                FILE *log);
LIBBACKENDTEST_EXPORTED int be_test_sorted(struct be_ctx *bectx,
                                           const struct be_params *bep,
                                           FILE *log);
LIBBACKENDTEST_EXPORTED int be_test_rand_norepeat(struct be_ctx *bectx,
                                                  const struct be_params *bep,
                                                  FILE *log);

LIBBACKENDTEST_EXPORTED int be_test_cross_check(struct be_ctx *bectx1,
                                                struct be_ctx *bectx2,
                                                const struct be_params *bep,
                                                void *ctx, FILE *log);

LIBBACKENDTEST_EXPORTED int be_test_perf(struct be_ctx *bectx,
                                         const struct be_params *bep,
                                         int (*reset_be)(struct be_ctx *));

LIBBACKENDTEST_EXPORTED int be_test_fill_drain(struct be_ctx *bectx,
                                               const struct be_params *bep,
                                               FILE *log);

LIBBACKENDTEST_EXPORTED int
    be_test_fill_drain_sorted(struct be_ctx *bectx, const struct be_params *bep,
                              FILE *log);

#endif

/* vi: set expandtab sw=4 ts=4: */
