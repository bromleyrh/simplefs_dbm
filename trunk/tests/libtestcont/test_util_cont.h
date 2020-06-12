/*
 * test_util_cont.h
 */

#ifndef _TEST_UTIL_CONT_H
#define _TEST_UTIL_CONT_H

#include "test_util_cont_common.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define CONFIG_PATH_ENV "TESTCONT_CONFIG_PATH"

#define DEFAULT_CONFIG_PATH "testcont_config.json"

struct cont_test_opts {
    struct cont_params  *contp;
    int                 order_stats;
    int                 (*parse_test_opt)(int, void *);
    void                *test_opts;
};

struct cont_params {
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
    unsigned    use_cont:1;
    unsigned    verify:1;
    unsigned    verify_after_search:1;
    unsigned    zero_keys:1;
};

struct cont_ops {
    int (*insert)(void *cont, void *key);
    int (*replace)(void *cont, void *key);
    int (*search)(void *cont, void *key, void *res);
    int (*range_search)(void *cont, void *key, void *res);
    int (*select)(void *cont, int idx, void *res);
    int (*get_index)(void *cont, void *key, int *idx);
    int (*delete)(void *cont, void *key);
    int (*delete_from)(void *cont, int node, void *res);
    int (*walk)(void *cont, void *startkey, int (*fn)(const void *, void *),
                void *ctx);
    int (*iter_new)(void **iter, void *cont);
    int (*iter_free)(void *iter);
    int (*iter_get)(void *iter, void *ret);
    int (*iter_prev)(void *iter);
    int (*iter_next)(void *iter);
    int (*iter_search)(void *iter, const void *key);
    int (*iter_select)(void *iter, int idx);
    int (*dump)(FILE *f, void *cont);
};

struct cont_ctx;
struct cont_cb {
    int (*init_walk_data)(struct cont_ctx *contctx, void *ctx);
    int (*free_walk_data)(struct cont_ctx *contctx, void *ctx, int error);
    int (*verify_insertion)(struct cont_ctx *contctx);
    int (*verify_rand)(struct cont_ctx *contctx);
    int (*verify_cmp)(struct cont_ctx *contctx1, struct cont_ctx *contctx2,
                      void *ctx);
    int (*print_stats)(FILE *f, struct cont_ctx *contctx, int times);
    int (*end_test)(struct cont_ctx *contctx);
};

#define SET_STD_OPS_NO_DUMP(contctx, prefix) \
    (contctx).ops.insert = (typeof((contctx).ops.insert))&(prefix ## _insert); \
    (contctx).ops.search = (typeof((contctx).ops.search))&(prefix ## _search); \
    (contctx).ops.select = NULL; \
    (contctx).ops.get_index = NULL; \
    (contctx).ops.delete = (typeof((contctx).ops.delete))&(prefix ## _delete); \
    (contctx).ops.dump = NULL

#define SET_STD_OPS(contctx, prefix) \
    (contctx).ops.insert = (typeof((contctx).ops.insert))&(prefix ## _insert); \
    (contctx).ops.search = (typeof((contctx).ops.search))&(prefix ## _search); \
    (contctx).ops.select = NULL; \
    (contctx).ops.get_index = NULL; \
    (contctx).ops.delete = (typeof((contctx).ops.delete))&(prefix ## _delete); \
    (contctx).ops.dump = (typeof((contctx).ops.dump))&(prefix ## _dump)

#define SET_ALL_OPS(contctx, prefix) \
    SET_STD_OPS(contctx, prefix); \
    (contctx).ops.select = (typeof((contctx).ops.select))&(prefix ## _select); \
    (contctx).ops.get_index \
        = (typeof((contctx).ops.get_index))&(prefix ## _get_index)

#define SET_REPLACE_OP(contctx, prefix) \
    (contctx).ops.replace = (typeof((contctx).ops.replace))&(prefix ## _replace)

#define SET_DELETE_FROM_OP(contctx, prefix) \
    (contctx).ops.delete_from = \
        (typeof((contctx).ops.delete_from))&(prefix ## _delete_from)

#define SET_RANGE_SEARCH_OP(contctx, prefix) \
    (contctx).ops.range_search \
        = (typeof((contctx).ops.range_search))&(prefix ## _range_search)

#define SET_WALK_OP(contctx, prefix) \
    (contctx).ops.walk = (typeof((contctx).ops.walk))&(prefix ## _walk)

#define SET_STD_ITER_OPS_NO_PREV(contctx, prefix) \
    (contctx).ops.iter_new \
        = (typeof((contctx).ops.iter_new))&(prefix ## _iter_new); \
    (contctx).ops.iter_free \
        = (typeof((contctx).ops.iter_free))&(prefix ## _iter_free); \
    (contctx).ops.iter_get \
        = (typeof((contctx).ops.iter_get))&(prefix ## _iter_get); \
    (contctx).ops.iter_prev = NULL; \
    (contctx).ops.iter_next \
        = (typeof((contctx).ops.iter_next))&(prefix ## _iter_next); \
    (contctx).ops.iter_search \
        = (typeof((contctx).ops.iter_search))&(prefix ## _iter_search); \
    (contctx).ops.iter_select = NULL

#define SET_STD_ITER_OPS(contctx, prefix) \
    SET_STD_ITER_OPS_NO_PREV(contctx, prefix); \
    (contctx).ops.iter_prev \
        = (typeof((contctx).ops.iter_prev))&(prefix ## _iter_prev)

#define SET_ALL_ITER_OPS(contctx, prefix) \
    SET_STD_ITER_OPS(contctx, prefix); \
    (contctx).ops.iter_select \
        = (typeof((contctx).ops.iter_select))&(prefix ## _iter_select)

struct cont_stats {
    uint64_t num_gen;
    uint64_t num_ops;
    uint64_t num_ops_start;
    uint64_t num_ops_out_of_range;
    uint64_t repeat_inserts;
    uint64_t invalid_replacements;
    uint64_t repeat_deletes;
    uint32_t num_keys;
};

struct cont_ctx {
    void                *cont;
    struct cont_ops     ops;
    int                 key_size;
    int                 max_key;
    int                 (*wfn)(const void *, void *);
    void                *wctx;
    struct cont_cb      cb;
    struct cont_stats   stats;
    void                *bmdata;
    void                *ctx;
};

extern LIBTESTCONT_EXPORTED void (*term_handler)(int);

#define MAX_KEY_SIZE 4096

LIBTESTCONT_EXPORTED int parse_cont_test_cmdline(int argc, char **argv,
                                                 const char *progusage,
                                                 const char *test_opt_str,
                                                 int (*parse_test_opt)(int,
                                                                       void *),
                                                 struct cont_params *contp,
                                                 void *test_opts, int *seed,
                                                 int *enable_mtrace,
                                                 int *run_gdb, int *shell,
                                                 int order_stats);

LIBTESTCONT_EXPORTED void init_cont_ctx(struct cont_ctx *contctx, void *bmdata,
                                        int key_size, int max_key);

LIBTESTCONT_EXPORTED int *get_full_key(int key, int key_size, int *buf);
LIBTESTCONT_EXPORTED int get_short_key(const int *full_key, int key_size);

LIBTESTCONT_EXPORTED int int_key_cmp(const void *k1, const void *k2, void *ctx);

LIBTESTCONT_EXPORTED const char *int_key_to_str(const void *k, void *ctx);

LIBTESTCONT_EXPORTED void cont_bitmap_set(struct cont_ctx *contctx, int key,
                                          int val, int record_stats);

LIBTESTCONT_EXPORTED int cont_insert(struct cont_ctx *contctx, int key,
                                     int *result, int repeat_allowed,
                                     int verbose, int record_stats);
LIBTESTCONT_EXPORTED int cont_replace(struct cont_ctx *contcx, int key,
                                      int *result, int nonexistent_allowed,
                                      int verbose, int record_stats);
LIBTESTCONT_EXPORTED int cont_delete(struct cont_ctx *contctx, int key,
                                     int *result, int repeat_allowed,
                                     int verbose, int record_stats);
LIBTESTCONT_EXPORTED int cont_delete_from(struct cont_ctx *contctx, int node,
                                          int *result, int repeat_allowed,
                                          int verbose, int record_stats);
LIBTESTCONT_EXPORTED int cont_find(struct cont_ctx *contctx, int key,
                                   int *result, int verbose, int record_stats);
LIBTESTCONT_EXPORTED int cont_range_find(struct cont_ctx *contctx, int key,
                                         int *result, int verbose,
                                         int record_stats);
LIBTESTCONT_EXPORTED int cont_select(struct cont_ctx *contctx, int idx,
                                     int *result, int verbose,
                                     int record_stats);
LIBTESTCONT_EXPORTED int cont_get_index(struct cont_ctx *contctx, int key,
                                        int *result, int verbose,
                                        int record_stats);
LIBTESTCONT_EXPORTED int cont_walk(struct cont_ctx *contctx, int startkey,
                                   int (*fn)(const void *, void *), void *ctx,
                                   int verbose, int record_stats);

LIBTESTCONT_EXPORTED int cont_iter_new(struct cont_ctx *contctx, void **result,
                                       int verbose, int record_stats);
LIBTESTCONT_EXPORTED int cont_iter_free(struct cont_ctx *contctx, void *iter,
                                        int verbose, int record_stats);
LIBTESTCONT_EXPORTED int cont_iter_get(struct cont_ctx *contctx, void *iter,
                                       int *result, int verbose,
                                       int record_stats);
LIBTESTCONT_EXPORTED int cont_iter_prev(struct cont_ctx *contctx, void *iter,
                                        int verbose, int record_stats);
LIBTESTCONT_EXPORTED int cont_iter_next(struct cont_ctx *contctx, void *iter,
                                        int verbose, int record_stats);
LIBTESTCONT_EXPORTED int cont_iter_search(struct cont_ctx *contctx, void *iter,
                                          int key, int verbose,
                                          int record_stats);
LIBTESTCONT_EXPORTED int cont_iter_select(struct cont_ctx *contctx, void *iter,
                                          int idx, int verbose,
                                          int record_stats);

LIBTESTCONT_EXPORTED int cont_test_quick(struct cont_ctx *contctx,
                                         const struct cont_params *contp);
LIBTESTCONT_EXPORTED int cont_test_insertion(struct cont_ctx *contctx,
                                             const struct cont_params *contp,
                                             FILE *log);
LIBTESTCONT_EXPORTED int cont_test_rand_repeat(struct cont_ctx *contctx,
                                               const struct cont_params *contp,
                                               FILE *log);
LIBTESTCONT_EXPORTED int cont_test_sorted(struct cont_ctx *contctx,
                                          const struct cont_params *contp,
                                          FILE *log);
LIBTESTCONT_EXPORTED int
    cont_test_rand_norepeat(struct cont_ctx *contctx,
                            const struct cont_params *contp, FILE *log);

LIBTESTCONT_EXPORTED int cont_test_cross_check(struct cont_ctx *contctx1,
                                               struct cont_ctx *contctx2,
                                               const struct cont_params *contp,
                                               void *ctx, FILE *log);

LIBTESTCONT_EXPORTED int cont_test_perf(struct cont_ctx *contctx,
                                        const struct cont_params *contp,
                                        int (*reset_cont)(struct cont_ctx *));

LIBTESTCONT_EXPORTED int cont_test_fill_drain(struct cont_ctx *contctx,
                                              const struct cont_params *contp,
                                              FILE *log);

LIBTESTCONT_EXPORTED int
    cont_test_fill_drain_sorted(struct cont_ctx *contctx,
                                const struct cont_params *contp, FILE *log);

#endif

/* vi: set expandtab sw=4 ts=4: */
