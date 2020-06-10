/*
 * test_util_cont.c
 */

#include "test_util_cont.h"
#include "test_util_cont_cmdline.h"
#include "test_util_cont_config.h"
#include "test_util_cont_util.h"
#include "util.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <avl_tree.h>
#include <bitmap.h>
#include <dynamic_array.h>
#include <strings_ext.h>

#include <test_util.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <search.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/time.h>

struct empty_cont_ctx {
    struct dynamic_array    *key_list;
    int                     key_size;
};

extern __thread int db_err_test;
extern __thread int db_io_err;
extern __thread int db_mem_err;

extern __thread int avl_tree_mem_test;
extern __thread int avl_tree_mem_err;
extern __thread int btree_mem_test;
extern __thread int btree_mem_err;

void (*term_handler)(int);

#define PERFORM_REPLACE(contp) (((contp)->test_replace) ? random() % 2 : 0)

#define RESET_ERR_TEST() \
    do { \
        ERR_CLEAR(db_io_err); \
        ERR_CLEAR(db_mem_err); \
        ERR_CLEAR(btree_mem_err); \
        ERR_CLEAR(avl_tree_mem_err); \
    } while (0)

#define DISABLE_ERR_TEST(tmp) \
    do { \
        (tmp) = db_err_test; \
        db_err_test = btree_mem_test = avl_tree_mem_test = 0; \
    } while (0)

#define ENABLE_ERR_TEST(tmp) \
    db_err_test = btree_mem_test = avl_tree_mem_test = (tmp)

static void lib_term_handler(int);

static void init_shuffle(long *, size_t);

static inline int negate_insert_ratio(int);

static int do_iter_seek_single(struct cont_ctx *, void *, unsigned *, int, int,
                               int,
                               int (*)(struct cont_ctx *, void *, int, int),
                               int (*)(const unsigned *, size_t, unsigned,
                                       unsigned *, int));
static int do_test_iter(struct cont_ctx *, void *, unsigned, int, int, int,
                        uint64_t *, uint64_t);

static int test_iter_funcs(struct cont_ctx *, int, uint64_t, int (*)(int, int),
                           int, int, int, int);

static int empty_cont_cb(const void *, void *);
#ifndef NDEBUG
static int cmp_nonzero_unsigned(const void *, const void *);
#endif

static int empty_container(struct cont_ctx *);

int
parse_cont_test_cmdline(int argc, char **argv, const char *progusage,
                        const char *test_opt_str,
                        int (*parse_test_opt)(int, void *),
                        struct cont_params *contp, void *test_opts, int *seed,
                        int *enable_mtrace, int *run_gdb, int *shell,
                        int order_stats)
{
    struct cont_test_opts *testopts = (struct cont_test_opts *)test_opts;

    testopts->contp = contp;
    testopts->order_stats = order_stats;
    testopts->parse_test_opt = parse_test_opt;
    testopts->test_opts = test_opts;

    return parse_test_cmdline(argc, argv,
                              cont_test_usage(progusage, order_stats),
                              cont_test_opt_str(test_opt_str, order_stats),
                              parse_cont_test_opt, test_opts, seed,
                              enable_mtrace, run_gdb, shell);
}

int
parse_cont_test_config(const char *path)
{
    return parse_config(path, &params);
}

void
init_cont_ctx(struct cont_ctx *contctx, void *bmdata, int key_size, int max_key)
{
    struct cont_stats *stats = &contctx->stats;

    contctx->key_size = key_size;
    contctx->max_key = max_key;

    stats->num_gen = 0;
    stats->num_ops = stats->num_ops_start = stats->num_ops_out_of_range = 0;
    stats->repeat_inserts = stats->repeat_deletes = 0;
    stats->invalid_replacements = 0;
    stats->num_keys = 0;

    contctx->bmdata = bmdata;
}

static void
lib_term_handler(int signum)
{
    if (quit == 0)
        quit = 1;
    else {
        int old_errno = errno;

        if (term_handler != NULL)
            (*term_handler)(signum);
        else {
            signal(signum, SIG_DFL);
            raise(signum);
        }
        errno = old_errno;
    }
}

static void
init_shuffle(long *seed, size_t seedlen)
{
    char *rem;
    div_t seedwords;
    int i;

    seedwords = div(seedlen, sizeof(*seed));

    for (i = 0; i < seedwords.quot; i++)
        seed[i] = random();

    rem = (char *)&seed[i];
    for (i = 0; i < seedwords.rem; i++)
        rem[i] = (char)(random() & 0xff);
}

#define MINUS_ZERO (INT_MIN / 8)

static inline int
negate_insert_ratio(int insert_ratio)
{
    if (insert_ratio == MINUS_ZERO)
        return 0;
    if (insert_ratio == 0)
        return MINUS_ZERO;

    return -insert_ratio;
}

#undef MINUS_ZERO

int *
get_full_key(int key, int key_size, int *buf)
{
    int i;

    key_size /= sizeof(int);

    for (i = 0; i < key_size; i++)
        buf[i] = key;

    return buf;
}

int
get_short_key(const int *full_key, int key_size)
{
    int i;
    int key = full_key[0];

    key_size /= sizeof(int);

    for (i = 1; i < key_size; i++) {
        if (full_key[i] != key)
            return -1;
    }

    return key;
}

int
int_key_cmp(const void *k1, const void *k2, void *ctx)
{
    int key1 = get_short_key((int *)k1, (intptr_t)ctx);
    int key2 = get_short_key((int *)k2, (intptr_t)ctx);

    return (key1 > key2) - (key1 < key2);
}

const char *
int_key_to_str(const void *k, void *ctx)
{
    int key = get_short_key((int *)k, (intptr_t)ctx);
    static char buf[16];

    snprintf(buf, sizeof(buf), "%d", key);
    return buf;
}

void
cont_bitmap_set(struct cont_ctx *contctx, int key, int val, int record_stats)
{
    struct bitmap_data *bmdata = (struct bitmap_data *)(contctx->bmdata);

    bitmap_set(bmdata->bitmap, key, val);

    if (record_stats)
        ++(contctx->stats.num_ops);
}

int
cont_insert(struct cont_ctx *contctx, int key, int *result, int repeat_allowed,
            int verbose, int record_stats)
{
    int buf[MAX_KEY_SIZE / sizeof(int)];
    int *full_key;
    int ret;

    (void)result;

    full_key = get_full_key(key, contctx->key_size, buf);

    ret = (*(contctx->ops.insert))(contctx->cont, (void *)full_key);
    if (ret == 0) {
        if (verbose > 1)
            fprintf(stderr, "Inserted %d\n", key);
        if (record_stats)
            ++(contctx->stats.num_keys);
    } else {
        if ((ret == -EADDRINUSE) && repeat_allowed) {
            if (verbose > 0)
                error(0, -ret, "Error inserting in container");
            if (record_stats)
                ++(contctx->stats.repeat_inserts);
        } else {
            error(0, -ret, "Error inserting in container");
            return ret;
        }
    }

    if (record_stats) {
        ++(contctx->stats.num_gen);
        ++(contctx->stats.num_ops);
        if ((contctx->max_key != -1) && (key > contctx->max_key))
            ++(contctx->stats.num_ops_out_of_range);
    }

    return 0;
}

int
cont_replace(struct cont_ctx *contctx, int key, int *result,
             int nonexistent_allowed, int verbose, int record_stats)
{
    int buf[MAX_KEY_SIZE / sizeof(int)];
    int *full_key;
    int ret;

    (void)result;

    full_key = get_full_key(key, contctx->key_size, buf);

    ret = (*(contctx->ops.replace))(contctx->cont, (void *)full_key);
    if (ret == 0) {
        if (verbose > 1)
            fprintf(stderr, "Replaced %d\n", key);
    } else {
        if ((ret == -EADDRNOTAVAIL) && nonexistent_allowed) {
            if (verbose > 0)
                error(0, -ret, "Error replacing data in container");
            if (record_stats)
                ++(contctx->stats.invalid_replacements);
        } else {
            error(0, -ret, "Error replacing data in container");
            return ret;
        }
    }

    if (record_stats) {
        ++(contctx->stats.num_gen);
        ++(contctx->stats.num_ops);
        if ((contctx->max_key != -1) && (key > contctx->max_key))
            ++(contctx->stats.num_ops_out_of_range);
    }

    return 0;
}

int
cont_delete(struct cont_ctx *contctx, int key, int *result, int repeat_allowed,
            int verbose, int record_stats)
{
    int buf[MAX_KEY_SIZE / sizeof(int)];
    int *full_key;
    int ret;

    (void)result;

    full_key = get_full_key(key, contctx->key_size, buf);

    ret = (*(contctx->ops.delete))(contctx->cont, (void *)full_key);
    if (ret == 0) {
        if (verbose > 1)
            fprintf(stderr, "Deleted %d\n", key);
        if (record_stats)
            --(contctx->stats.num_keys);
    } else {
        if ((ret == -EADDRNOTAVAIL) && repeat_allowed) {
            if (verbose > 0)
                error(0, -ret, "Error deleting from container");
            if (record_stats)
                ++(contctx->stats.repeat_deletes);
        } else {
            error(0, -ret, "Error deleting from container");
            return ret;
        }
    }

    if (record_stats) {
        ++(contctx->stats.num_ops);
        if ((contctx->max_key != -1) && (key > contctx->max_key))
            ++(contctx->stats.num_ops_out_of_range);
    }

    return 0;
}

int
cont_delete_from(struct cont_ctx *contctx, int node, int *result,
                 int repeat_allowed, int verbose, int record_stats)
{
    int ret;

    ret = (*(contctx->ops.delete_from))(contctx->cont, node, result);
    if (ret == 0) {
        if (verbose > 1)
            fprintf(stderr, "Deleted %d from node\n", *result);
        if (record_stats)
            --(contctx->stats.num_keys);
    } else {
        if ((ret == -EADDRNOTAVAIL) && repeat_allowed) {
            if (verbose > 0)
                error(0, -ret, "Error deleting from container");
            if (record_stats)
                ++(contctx->stats.repeat_deletes);
            *result = -1;
        } else {
            error(0, -ret, "Error deleting from container");
            return ret;
        }
    }

    if (record_stats)
        ++(contctx->stats.num_ops);

    return 0;
}

int
cont_find(struct cont_ctx *contctx, int key, int *result, int verbose,
          int record_stats)
{
    int buf[MAX_KEY_SIZE / sizeof(int)];
    int *full_key;
    int res[MAX_KEY_SIZE / sizeof(int)];
    int ret;

    (void)result;

    full_key = get_full_key(key, contctx->key_size, buf);

    ret = (*(contctx->ops.search))(contctx->cont, (void *)full_key, res);
    if (ret == 1) {
        if (verbose)
            fprintf(stderr, "Key %d found\n", key);
    } else if (ret == 0) {
        if (verbose)
            fprintf(stderr, "Key %d not found\n", key);
    } else {
        error(0, -ret, "Error looking up in container");
        return ret;
    }

    if (record_stats) {
        ++(contctx->stats.num_ops);
        if ((contctx->max_key != -1) && (key > contctx->max_key))
            ++(contctx->stats.num_ops_out_of_range);
    }

    return ret;
}

int
cont_range_find(struct cont_ctx *contctx, int key, int *result, int verbose,
                int record_stats)
{
    int buf[MAX_KEY_SIZE / sizeof(int)];
    int *full_key;
    int res[MAX_KEY_SIZE / sizeof(int)];
    int ret;

    (void)result;
    (void)verbose;

    full_key = get_full_key(key, contctx->key_size, buf);

    ret = (*(contctx->ops.range_search))(contctx->cont, (void *)full_key, res);
    if ((ret != 0) && (ret != 1)) {
        error(0, -ret, "Error looking up in container");
        return ret;
    }

    if (record_stats) {
        ++(contctx->stats.num_ops);
        if ((contctx->max_key != -1) && (key > contctx->max_key))
            ++(contctx->stats.num_ops_out_of_range);
    }

    return ret;
}

int
cont_select(struct cont_ctx *contctx, int idx, int *result, int verbose,
            int record_stats)
{
    int res[MAX_KEY_SIZE / sizeof(int)];
    int ret, short_res;

    ret = (*(contctx->ops.select))(contctx->cont, idx, res);
    if (ret == 1) {
        short_res = get_short_key(res, contctx->key_size);
        if (result != NULL)
            *result = short_res;
        if (verbose)
            fprintf(stderr, "Key at index %d is %d\n", idx, short_res);
    } else if (ret == 0) {
        if (verbose)
            fprintf(stderr, "Key at index %d not found\n", idx);
    } else {
        assert(ret < 0);
        error(0, -ret, "Error looking up in container");
        return ret;
    }

    if (record_stats) {
        ++(contctx->stats.num_ops);
        if ((contctx->max_key != -1) && (idx > contctx->max_key))
            ++(contctx->stats.num_ops_out_of_range);
    }

    return ret;
}

int
cont_get_index(struct cont_ctx *contctx, int key, int *result, int verbose,
               int record_stats)
{
    int buf[MAX_KEY_SIZE / sizeof(int)];
    int *full_key;
    int res, ret;

    full_key = get_full_key(key, contctx->key_size, buf);

    ret = (*(contctx->ops.get_index))(contctx->cont, (void *)full_key, &res);
    if (ret == 1) {
        if (result != NULL)
            *result = res;
        if (verbose)
            fprintf(stderr, "Key %d has index %d\n", key, res);
    } else if (ret == 0) {
        if (verbose)
            fprintf(stderr, "Key %d not found\n", key);
    } else {
        assert(ret < 0);
        error(0, -ret, "Error looking up in container");
        return ret;
    }

    if (record_stats) {
        ++(contctx->stats.num_ops);
        if ((contctx->max_key != -1) && (key > contctx->max_key))
            ++(contctx->stats.num_ops_out_of_range);
    }

    return ret;
}

int
cont_walk(struct cont_ctx *contctx, int startkey,
          int (*fn)(const void *, void *), void *ctx, int verbose,
          int record_stats)
{
    int buf[MAX_KEY_SIZE / sizeof(int)];
    int *full_key;
    int ret;

    (void)verbose;
    (void)record_stats;

    full_key = get_full_key(startkey, contctx->key_size, buf);

    while ((ret = (*(contctx->ops.walk))(contctx->cont, (void *)full_key, fn,
                                         ctx)) == 1)
        ;
    if (ret != 0)
        error(0, -ret, "Error walking container");

    return ret;
}

int
cont_iter_new(struct cont_ctx *contctx, void **result, int verbose,
              int record_stats)
{
    int ret;
    void *res;

    (void)verbose;
    (void)record_stats;

    ret = (*(contctx->ops.iter_new))(&res, contctx->cont);
    if (ret == 0) {
        if (result != NULL)
            *result = res;
    } else if (ret != -ENOENT)
        error(0, -ret, "Error creating iterator");

    return ret;
}

int
cont_iter_free(struct cont_ctx *contctx, void *iter, int verbose,
               int record_stats)
{
    int ret;

    (void)verbose;
    (void)record_stats;

    ret = (*(contctx->ops.iter_free))(iter);
    if (ret != 0)
        error(0, -ret, "Error freeing iterator");

    return ret;
}

int
cont_iter_get(struct cont_ctx *contctx, void *iter, int *result, int verbose,
              int record_stats)
{
    int res[MAX_KEY_SIZE / sizeof(int)];
    int ret, short_res;

    (void)record_stats;

    ret = (*(contctx->ops.iter_get))(iter, res);
    if (ret == 0) {
        short_res = get_short_key(res, contctx->key_size);
        if (result != NULL)
            *result = short_res;
        if (verbose)
            fprintf(stderr, "Key at iterator position is %d\n", short_res);
    } else
        error(0, -ret, "Error accessing container element");

    return ret;
}

int
cont_iter_prev(struct cont_ctx *contctx, void *iter, int verbose,
               int record_stats)
{
    int ret;

    (void)verbose;
    (void)record_stats;

    ret = (*(contctx->ops.iter_prev))(iter);
    if ((ret != 0) && (ret != -EADDRNOTAVAIL))
        error(0, -ret, "Error decrementing iterator");

    return ret;
}

int
cont_iter_next(struct cont_ctx *contctx, void *iter, int verbose,
               int record_stats)
{
    int ret;

    (void)verbose;
    (void)record_stats;

    ret = (*(contctx->ops.iter_next))(iter);
    if ((ret != 0) && (ret != -EADDRNOTAVAIL))
        error(0, -ret, "Error incrementing iterator");

    return ret;
}

int
cont_iter_search(struct cont_ctx *contctx, void *iter, int key, int verbose,
                 int record_stats)
{
    int buf[MAX_KEY_SIZE / sizeof(int)];
    int *full_key;
    int ret;

    (void)record_stats;

    full_key = get_full_key(key, contctx->key_size, buf);

    ret = (*(contctx->ops.iter_search))(iter, full_key);
    if (ret == 1) {
        if (verbose)
            fprintf(stderr, "Key %d found\n", key);
    } else if (ret == 0) {
        if (verbose)
            fprintf(stderr, "Key %d not found\n", key);
    } else {
        assert(ret < 0);
        error(0, -ret, "Error setting iterator position");
    }

    return ret;
}

int
cont_iter_select(struct cont_ctx *contctx, void *iter, int idx, int verbose,
                 int record_stats)
{
    int ret;

    (void)record_stats;

    ret = (*(contctx->ops.iter_select))(iter, idx);
    if (ret == 1) {
        if (verbose)
            fprintf(stderr, "Key at index %d found\n", idx);
    } else if (ret == 0) {
        if (verbose)
            fprintf(stderr, "Key at index %d not found\n", idx);
    } else {
        assert(ret < 0);
        error(0, -ret, "Error setting iterator position");
    }

    return ret;
}

static int
do_iter_seek_single(struct cont_ctx *contctx, void *iter, unsigned *curkey,
                    int dir, int use_cont, int use_bitmap,
                    int (*contseekfn)(struct cont_ctx *, void *, int, int),
                    int (*bmseekfn)(const unsigned *, size_t, unsigned,
                                    unsigned *, int))
{
    int range_end = 0, res, ret = 0;
    struct bitmap_data *bmdata;
    unsigned oldkey = 0;

    if (use_cont) {
        ret = (*contseekfn)(contctx, iter, 0, 1);
        RESET_ERR_TEST();
        if (ret == 0) {
            for (;;) {
                ret = cont_iter_get(contctx, iter, &res, 0, 1);
                RESET_ERR_TEST();
                if (ret == 0) {
                    ret = 1;
                    break;
                }
                if (ERROR_FATAL(ret))
                    goto err;
            }
        } else {
            if (ret != -EADDRNOTAVAIL)
                goto err;
            range_end = 1;
            ret = 0;
        }
    }

    if (use_bitmap) {
        int tmp;

        bmdata = (struct bitmap_data *)(contctx->bmdata);

        oldkey = *curkey;
        if ((dir == 0) && (*curkey == 0))
            tmp = 0;
        else {
            *curkey = (dir == 0) ? *curkey - 1 : *curkey + 1;
            tmp = (*bmseekfn)(bmdata->bitmap, bmdata->bitmap_len, *curkey,
                              curkey, 1);
            if (tmp == 0)
                *curkey = oldkey;
        }
        if (use_cont && (tmp != ret)) {
            error(0, 0, "Bitmap and iterator differ seeking %s from %u (%d "
                  "vs. %d)", (dir == 0) ? "left" : "right", oldkey, !ret, ret);
            return -EIO;
        }
    }

    if (use_cont && use_bitmap && (ret == 1)) {
        if ((unsigned)res == *curkey)
            fprintf(stderr, "\rBitmap and iterator agree up to %9d", res);
        else {
            error(0, 0, "Bitmap and iterator differ at key %s of %u (%u vs. "
                  "%d)", (dir == 0) ? "left" : "right", oldkey, *curkey, res);
            return -EIO;
        }
    }

    return range_end ? 2 : 0;

err:
    return ret;
}

static int
do_test_iter(struct cont_ctx *contctx, void *iter, unsigned startkey,
             int max_key, int use_cont, int use_bitmap, uint64_t *n,
             uint64_t num_ops)
{
    int dir, range_end = 0;
    int ret;
    uint64_t nseeks = 0;
    unsigned curkey;

    curkey = startkey;
    dir = (contctx->ops.iter_prev == NULL) ? 1 : (random() % 2);

    for (;;) {
        int i;
        int (*bmseekfn)(const unsigned *, size_t, unsigned, unsigned *, int);
        int (*contseekfn)(struct cont_ctx *, void *, int, int);
        int seeklen;

        if (dir == 0) {
            contseekfn = &cont_iter_prev;
            bmseekfn = &bitmap_find_prev_set;
        } else {
            contseekfn = &cont_iter_next;
            bmseekfn = &bitmap_find_next_set;
        }

        i = 0;
        seeklen = random() % (max_key/2);
        while (i < seeklen) {
            ret = do_iter_seek_single(contctx, iter, &curkey, dir, use_cont,
                                      use_bitmap, contseekfn, bmseekfn);
            if (ERROR_FATAL(ret))
                return ret;
            if (++(*n) == num_ops)
                goto end;
            if (ret == 0) {
                ++i;
                ++nseeks;
            } else if (ret == 2) {
                if (range_end)
                    return 0;
                range_end = 1;
                break;
            }
        }

        if (!(random() % 8) || quit)
            break;
        dir = !dir;
    }

end:
    if (nseeks > 0)
        fputc('\n', stderr);
    return 0;
}

static int
test_iter_funcs(struct cont_ctx *contctx, int test_iter_only, uint64_t num_ops,
                int (*gen_key_fn)(int, int), int max_key,
                int out_of_range_interval, int use_cont, int use_bitmap)
{
    int ret;
    struct bitmap_data *bmdata;
    uint64_t n;
    void *iter = NULL;

    if (use_cont) {
        for (;;) {
            ret = cont_iter_new(contctx, &iter, 0, 1);
            RESET_ERR_TEST();
            if (ret == 0)
                break;
            if (!ERROR_FATAL(ret))
                continue;
            if (ret != -ENOENT)
                goto err1;
            if (contctx->stats.num_keys != 0) {
                error(0, 0, "Bitmap and container differ");
                ret = -EIO;
                goto err1;
            }
            return 0;
        }
    }
    bmdata = (struct bitmap_data *)(contctx->bmdata);

    n = 0;
    while (n < num_ops) {
        int key;
        int tmp;
        unsigned next;

        if (test_iter_only && use_bitmap
            && (bitmap_find_next_set(bmdata->bitmap, bmdata->bitmap_len, 0,
                                     &next, 0) == 1))
            key = next;
        else
            key = (*gen_key_fn)(max_key, out_of_range_interval);

        if (use_cont) {
            for (;;) {
                ret = cont_iter_search(contctx, iter, key, 0, 1);
                RESET_ERR_TEST();
                if (ret >= 0)
                    break;
                if (ERROR_FATAL(ret))
                    goto err2;
            }
        } else
            ret = 0;

        if (use_bitmap) {
            tmp = (key < (int)(bmdata->size))
                  ? bitmap_get(bmdata->bitmap, key) : 0;

            if ((tmp != ret) && use_cont) {
                error(0, 0, "Bitmap and container differ at %d (%d vs. %d)",
                      key, !ret, ret);
                ret = -EIO;
                goto err2;
            }
        } else
            tmp = 0;

        if ((ret == 1) || (tmp == 1)) {
            ret = do_test_iter(contctx, iter, (unsigned)key, max_key, use_cont,
                               use_bitmap, &n, num_ops);
            if (ret != 0)
                goto err2;
        }

        if ((!test_iter_only && !(random() % 16)) || quit)
            break;
    }

    if (!use_cont)
        return 0;

    for (;;) {
        ret = cont_iter_free(contctx, iter, 0, 1);
        RESET_ERR_TEST();
        if ((ret == 0) || ERROR_FATAL(ret))
            break;
    }
    return ret;

err2:
    if (use_cont)
        cont_iter_free(contctx, iter, 0, 0);
err1:
    return ret;
}

static int
empty_cont_cb(const void *k, void *ctx)
{
    int key;
    struct empty_cont_ctx *wctx = (struct empty_cont_ctx *)ctx;

    key = get_short_key((int *)k, wctx->key_size);

    return dynamic_array_push_back(wctx->key_list, &key);
}

#ifndef NDEBUG
static int
cmp_nonzero_unsigned(const void *k, const void *e)
{
    unsigned uword = *(unsigned *)e;

    (void)k;

    return (uword == 0);
}

#endif
static int
empty_container(struct cont_ctx *contctx)
{
    int err;
    int err_test_old;
    int *keys;
    size_t i, n;
    struct bitmap_data *bmdata = (struct bitmap_data *)(contctx->bmdata);
    struct dynamic_array *key_list;
    struct empty_cont_ctx wctx;

    fputs("Emptying container\n", stderr);

    err = dynamic_array_new(&key_list, 1024, sizeof(int));
    if (err) {
        error(0, -err, "Error allocating memory");
        return err;
    }

    wctx.key_list = key_list;
    wctx.key_size = contctx->key_size;
    DISABLE_ERR_TEST(err_test_old);
    err = (*(contctx->ops.walk))(contctx->cont, NULL, &empty_cont_cb, &wctx);
    ENABLE_ERR_TEST(err_test_old);
    if (err) {
        error(0, -err, "Error walking container");
        goto err;
    }

    err = dynamic_array_size(key_list, &n);
    if (err)
        goto err;
    keys = (int *)dynamic_array_buf(key_list);

    for (i = 0; !quit && (i < n); i++) {
        int buf[MAX_KEY_SIZE / sizeof(int)];

        for (;;) {
            err = (*(contctx->ops.delete))(contctx->cont,
                                           get_full_key(keys[i],
                                                        contctx->key_size,
                                                        buf));
            RESET_ERR_TEST();
            if (!err)
                break;
            if (!db_err_test
                || ((err != -ENOMEM) && (err != -EIO) && (err != -EBADF))) {
                error(0, -err, "Error removing from container");
                goto err;
            }
        }
        bitmap_set(bmdata->bitmap, keys[i], 0);
        --(contctx->stats.num_keys);
        fprintf(stderr, "\rRemoved %6d (%6zu/%6zu)", keys[i], i + 1, n);
    }
    if (i > 0)
        fputc('\n', stderr);

    if (i == n) {
        assert(memcchr(bmdata->bitmap, 0, bmdata->bitmap_len * sizeof(unsigned))
               == NULL);
        assert(lfind(NULL, bmdata->bitmap, &bmdata->bitmap_len,
                     sizeof(unsigned), &cmp_nonzero_unsigned)
               == NULL);
    }

    dynamic_array_free(key_list);

    return 0;

err:
    dynamic_array_free(key_list);
    return err;
}

int
cont_test_quick(struct cont_ctx *contctx, const struct cont_params *contp)
{
    const int testvals[] = {1, 2, 3, 4, 5, 6, 7};
    const int numtestvals = ARRAY_SIZE(testvals);
    int i;
    int ret;

    for (i = 0; i < numtestvals; i++) {
        ret = cont_insert(contctx, testvals[i], NULL, 0, 1, 1);
        if (ERROR_FATAL(ret))
            return ret;
        if (contp->dump) {
            ret = (*(contctx->ops.dump))(stdout, contctx->cont);
            if (ret != 0) {
                error(0, -ret, "Error dumping container");
                return ret;
            }
            fputs("--------------------------------------------------\n",
                  stdout);
        }
    }

    for (i = i - 1; i >= 0; i--) {
        ret = cont_delete(contctx, testvals[i], NULL, 0, 1, 1);
        if (ERROR_FATAL(ret))
            return ret;
        if (contp->dump) {
            ret = (*(contctx->ops.dump))(stdout, contctx->cont);
            if (ret != 0) {
                error(0, -ret, "Error dumping container");
                return ret;
            }
            fputs("--------------------------------------------------\n",
                  stdout);
        }
    }

    return 0;
}

int
cont_test_insertion(struct cont_ctx *contctx, const struct cont_params *contp,
                    FILE *log)
{
    int i;
    int ret = 0, tmp;

    if ((set_signal_handler(SIGINT, &lib_term_handler) == -1)
        || (set_signal_handler(SIGTERM, &lib_term_handler) == -1)
        || (set_signal_handler(SIGHUP, &pipe_handler) == -1)
        || (set_signal_handler(SIGPIPE, &pipe_handler) == -1)) {
        ret = -errno;
        error(0, errno, "Couldn't set signal handler");
        return ret;
    }

    for (i = 0; !quit; i++) {
        int key = random();

        ret = cont_insert(contctx, key, NULL, 1, 0, 1);
        if (ERROR_FATAL(ret))
            break;
        if (contp->dump) {
            ret = (*(contctx->ops.dump))(stdout, contctx->cont);
            if (ret != 0) {
                error(0, -ret, "Error dumping container");
                break;
            }
        }
        if (contp->verify && !(random() % contp->verification_period)) {
            ret = (*(contctx->cb.verify_insertion))(contctx);
            if (ret != 0)
                break;
        }
        VERBOSE_LOG(log, "ins %d\n", key);
    }

    if (contctx->cb.end_test != NULL) {
        tmp = (*(contctx->cb.end_test))(contctx);
        if (tmp != 0)
            ret = tmp;
    }

    restore_default_handler(SIGINT);
    restore_default_handler(SIGTERM);

    return ret;
}

int
cont_test_rand_repeat(struct cont_ctx *contctx, const struct cont_params *contp,
                      FILE *log)
{
    int (*gen_key_fn)(int, int);
    int delete_from_root = 0;
    int insert_ratio;
    int purge = 0;
    int ret = 0, tmp;
    int test_iter_only;
    struct perf_cmp_hdl *perf_cmp_hdl = NULL;

    if ((check_insert_ratio(contp) != 0) || (check_search_period(contp) != 0)
        || (check_max_key(contp) != 0)
        || (contp->test_order_stats && (check_order_stats(contctx) != 0)))
        return -EINVAL;

    if ((set_signal_handler(SIGINT, &lib_term_handler) == -1)
        || (set_signal_handler(SIGTERM, &lib_term_handler) == -1)
        || (set_signal_handler(SIGHUP, &pipe_handler) == -1)
        || (set_signal_handler(SIGPIPE, &pipe_handler) == -1)
        || (set_signal_handler(SIGUSR1, &usr1_handler) == -1)
        || (set_signal_handler(SIGUSR2, &usr2_handler) == -1)) {
        ret = -errno;
        error(0, errno, "Couldn't set signal handler");
        return ret;
    }

    test_iter_only = (contp->test_iter == 2);

    gen_key_fn = contp->zero_keys ? &gen_key : &gen_key_no_zero;
    insert_ratio = contp->insert_ratio;

    perf_cmp_wait(&perf_cmp_hdl);

    while (!quit && (NUM_OPS(contctx) < contp->num_ops)) {
        int key;
        int delete, search;
        int verify = -1;

        ret = handle_usr_signals(contctx, NULL, NULL);
        if (ret != 0)
            break;

        if (test_iter_only)
            delete_from_root = 0;
        else if (contp->delete_from_root) {
            if (!delete_from_root)
                delete_from_root = !(random() % 4096);
            else
                delete_from_root = !!(random() % 16384);
        }
        if (delete_from_root) {
            ret = auto_test_delete_from(contctx, 0, &key, contp->use_cont,
                                        contp->use_bitmap, 1, contp->confirm);
            if (ERROR_FATAL(ret))
                break;
            if (ret == 2)
                verify = 1;
            VERBOSE_LOG(stderr, "deleted %d from root\n"
                        "--------------------------------------------------"
                        "\n",
                        key);
        } else {
            search = test_iter_only ? 0 : !(random() % contp->search_period);
            if (search) {
                key = (*gen_key_fn)(contp->max_key, params.out_of_range_period);
                if (contp->test_walk)
                    search = random() % (contp->test_order_stats ? 4 : 2);
                else
                    search = 1 + random() % (contp->test_order_stats ? 3 : 1);
                switch (search) {
                case 0:
                    ret = auto_test_walk(contctx, key, contp->use_cont,
                                         contp->use_bitmap);
                    break;
                case 1:
                    if (contp->test_range_search && (random() % 2 == 0)) {
                        ret = auto_test_range_search(contctx, key,
                                                     contp->use_cont,
                                                     contp->use_bitmap);
                    } else {
                        ret = auto_test_search(contctx, key, contp->use_cont,
                                               contp->use_bitmap);
                    }
                    break;
                case 2:
                    ret = auto_test_select(contctx, key, contp->use_cont,
                                           contp->use_bitmap);
                    break;
                case 3:
                    ret = auto_test_get_index(contctx, key, contp->use_cont,
                                              contp->use_bitmap);
                    break;
                default:
                    ret = -EIO;
                    goto end;
                }
                if (ERROR_FATAL(ret))
                    break;
                if (!(contp->verify_after_search))
                    verify = 0;
            } else if (test_iter_only
                       || (contp->test_iter
                           && !(random() % params.iter_test_period))) {
                ret = test_iter_funcs(contctx, test_iter_only,
                                      test_iter_only
                                      ? contp->num_ops : UINT64_MAX,
                                      gen_key_fn, contp->max_key,
                                      params.iter_test_out_of_range_period,
                                      contp->use_cont, contp->use_bitmap);
                if (ret != 0)
                    break;
                if (test_iter_only)
                    quit = 1;
                if (!(contp->verify_after_search))
                    verify = 0;
            } else {
                if (!purge) {
                    purge = !(random() % params.purge_interval);
                    if (purge) {
                        insert_ratio = negate_insert_ratio(insert_ratio)
                                       * params.purge_factor;
                    }
                } else {
                    purge = !!(random() % params.purge_period);
                    if (!purge) {
                        insert_ratio
                            = negate_insert_ratio(insert_ratio
                                                  / params.purge_factor);
                    }
                }

                delete = (insert_ratio > 0) ? !(random() % (insert_ratio+1))
                         : !!(random() % -(insert_ratio+1));

                if (!delete) {
                    int replace = PERFORM_REPLACE(contp);

                    key = (*gen_key_fn)(contp->max_key, 0);
                    VERBOSE_LOG(log, "%s %d\n", replace ? "upd" : "ins", key);
                    ret = auto_test_insert(contctx, key, replace,
                                           contp->use_cont, contp->use_bitmap,
                                           1, 1, contp->confirm);
                    if (ERROR_FATAL(ret))
                        break;
                    if (ret == -ENOSPC) {
                        if (contp->empty_on_fill) {
                            ret = empty_container(contctx);
                            if (ret != 0)
                                break;
                        } else {
                            insert_ratio = -INT_MAX;
                            purge = 1;
                        }
                    } else if (ret == 2)
                        verify = 1;
                    VERBOSE_LOG(stderr, "%s %d\n"
                        "--------------------------------------------------"
                        "\n",
                        replace ? "replaced" : "inserted", key);
                } else {
                    key = (*gen_key_fn)(contp->max_key,
                                        params.out_of_range_period);
                    VERBOSE_LOG(log, "del %d\n", key);
                    ret = auto_test_delete(contctx, key, contp->use_cont,
                                           contp->use_bitmap, 1,
                                           contp->confirm);
                    if (ERROR_FATAL(ret))
                        break;
                    if (ret == 2)
                        verify = 1;
                    VERBOSE_LOG(stderr, "deleted %d\n"
                        "--------------------------------------------------"
                        "\n",
                        key);
                }
            }
        }

        if (contp->verify
            && ((verify == 1)
                || ((verify != 0)
                    && !(random() % contp->verification_period)))) {
            ret = (*(contctx->cb.verify_rand))(contctx);
            if (ret != 0)
                break;
        } else
            ret = 0;

        if (contp->verbose_stats)
            refresh_stat_output(contctx);
    }

end:

    if (perf_cmp_hdl != NULL)
        perf_cmp_finish(perf_cmp_hdl);

    if (contctx->cb.end_test != NULL) {
        tmp = (*(contctx->cb.end_test))(contctx);
        if (tmp != 0)
            ret = tmp;
    }

    restore_default_handler(SIGINT);
    restore_default_handler(SIGTERM);
    restore_default_handler(SIGUSR1);
    restore_default_handler(SIGUSR2);

    return ret;
}

int
cont_test_sorted(struct cont_ctx *contctx, const struct cont_params *contp,
                 FILE *log)
{
    int delete = 0, direction = 1;
    int (*gen_key_fn)(int, int);
    int key;
    int ret = 0, tmp;
    struct perf_cmp_hdl *perf_cmp_hdl = NULL;

    if ((check_search_period(contp) != 0) || (check_max_key(contp) != 0)
        || (contp->test_order_stats && (check_order_stats(contctx) != 0)))
        return -EINVAL;

    if ((set_signal_handler(SIGINT, &lib_term_handler) == -1)
        || (set_signal_handler(SIGTERM, &lib_term_handler) == -1)
        || (set_signal_handler(SIGHUP, &pipe_handler) == -1)
        || (set_signal_handler(SIGPIPE, &pipe_handler) == -1)
        || (set_signal_handler(SIGUSR1, &usr1_handler) == -1)
        || (set_signal_handler(SIGUSR2, &usr2_handler) == -1)) {
        ret = -errno;
        error(0, errno, "Couldn't set signal handler");
        return ret;
    }

    gen_key_fn = contp->zero_keys ? &gen_key : &gen_key_no_zero;

    perf_cmp_wait(&perf_cmp_hdl);

    key = (*gen_key_fn)(contp->max_key, 0);
    while (!quit && (NUM_OPS(contctx) < contp->num_ops)) {
        int search;
        int verify = -1;

        ret = handle_usr_signals(contctx, NULL, NULL);
        if (ret != 0)
            break;

        if (direction) {
            if ((key < contp->max_key) || delete)
                ++key;
        } else {
            if (key > !(contp->zero_keys))
                --key;
        }

        search = !(random() % contp->search_period);
        if (search) {
            if (contp->test_walk)
                search = random() % (contp->test_order_stats ? 4 : 2);
            else
                search = 1 + random() % (contp->test_order_stats ? 3 : 1);
            switch (search) {
            case 0:
                ret = auto_test_walk(contctx, key, contp->use_cont,
                                     contp->use_bitmap);
                break;
            case 1:
                if (contp->test_range_search && (random() % 2 == 0)) {
                    ret = auto_test_range_search(contctx, key, contp->use_cont,
                                                 contp->use_bitmap);
                } else {
                    ret = auto_test_search(contctx, key, contp->use_cont,
                                           contp->use_bitmap);
                }
                break;
            case 2:
                ret = auto_test_select(contctx, key, contp->use_cont,
                                       contp->use_bitmap);
                break;
            case 3:
                ret = auto_test_get_index(contctx, key, contp->use_cont,
                                          contp->use_bitmap);
                break;
            default:
                ret = -EIO;
                goto end;
            }
            if (ERROR_FATAL(ret))
                break;
            if (!(contp->verify_after_search))
                verify = 0;
        } else {
            if (!(random() % params.sorted_test_period)) {
                delete = random() % 2;
                direction = random() % 2;
                key = (*gen_key_fn)(contp->max_key,
                                    delete ? params.out_of_range_period : 0);
            }
            if (!delete) {
                int replace = PERFORM_REPLACE(contp);

                VERBOSE_LOG(log, "%s %d\n", replace ? "upd" : "ins", key);
                ret = auto_test_insert(contctx, key, replace, contp->use_cont,
                                       contp->use_bitmap, 1, 1, contp->confirm);
                if (ERROR_FATAL(ret))
                    break;
                if ((ret == -ENOSPC) && contp->empty_on_fill) {
                    ret = empty_container(contctx);
                    if (ret != 0)
                        break;
                } else if (ret == 2)
                    verify = 1;
                VERBOSE_LOG(stderr, "%s %d\n"
                            "--------------------------------------------------"
                            "\n",
                            replace ? "replaced" : "inserted", key);
            } else {
                VERBOSE_LOG(log, "del %d\n", key);
                ret = auto_test_delete(contctx, key, contp->use_cont,
                                       contp->use_bitmap, 1, contp->confirm);
                if (ERROR_FATAL(ret))
                    break;
                if (ret == 2)
                    verify = 1;
                VERBOSE_LOG(stderr, "deleted %d\n"
                            "--------------------------------------------------"
                            "\n",
                            key);
            }
        }

        if (contp->verify
            && ((verify == 1)
                || ((verify != 0)
                    && !(random() % contp->verification_period)))) {
            ret = (*(contctx->cb.verify_rand))(contctx);
            if (ret != 0)
                break;
        } else
            ret = 0;

        if (contp->verbose_stats)
            refresh_stat_output(contctx);
    }

end:

    if (perf_cmp_hdl != NULL)
        perf_cmp_finish(perf_cmp_hdl);

    if (contctx->cb.end_test != NULL) {
        tmp = (*(contctx->cb.end_test))(contctx);
        if (tmp != 0)
            ret = tmp;
    }

    restore_default_handler(SIGINT);
    restore_default_handler(SIGTERM);
    restore_default_handler(SIGUSR1);
    restore_default_handler(SIGUSR2);

    return ret;
}

int
cont_test_rand_norepeat(struct cont_ctx *contctx,
                        const struct cont_params *contp, FILE *log)
{
    int delete_from_root = 0;
    int (*gen_key_fn)(int, int);
    int ret = 0, tmp;
    struct bitmap_data *bmdata;
    struct perf_cmp_hdl *perf_cmp_hdl = NULL;

    if ((check_search_period(contp) != 0) || (check_max_key(contp) != 0)
        || (contp->test_order_stats && (check_order_stats(contctx) != 0)))
        return -EINVAL;

    if ((set_signal_handler(SIGINT, &lib_term_handler) == -1)
        || (set_signal_handler(SIGTERM, &lib_term_handler) == -1)
        || (set_signal_handler(SIGHUP, &pipe_handler) == -1)
        || (set_signal_handler(SIGPIPE, &pipe_handler) == -1)
        || (set_signal_handler(SIGUSR1, &usr1_handler) == -1)
        || (set_signal_handler(SIGUSR2, &usr2_handler) == -1)) {
        ret = -errno;
        error(0, errno, "Couldn't set signal handler");
        return ret;
    }

    bmdata = (struct bitmap_data *)(contctx->bmdata);
    gen_key_fn = contp->zero_keys ? &gen_key : &gen_key_no_zero;

    perf_cmp_wait(&perf_cmp_hdl);

    while (!quit && (NUM_OPS(contctx) < contp->num_ops)) {
        int key;
        int delete, search;
        int verify = -1;

        ret = handle_usr_signals(contctx, NULL, NULL);
        if (ret != 0)
            break;

        if (contp->delete_from_root) {
            if (!delete_from_root)
                delete_from_root = !(random() % 4096);
            else
                delete_from_root = !!(random() % 16384);
        }
        if (delete_from_root) {
            ret = auto_test_delete_from(contctx, 0, &key, contp->use_cont,
                                        contp->use_bitmap, 1, contp->confirm);
            if (ERROR_FATAL(ret))
                break;
            if (ret == 2)
                verify = 1;
            VERBOSE_LOG(stderr, "deleted %d from root\n"
                        "--------------------------------------------------"
                        "\n",
                        key);
        } else {
            key = (*gen_key_fn)(contp->max_key, 0);

            search = !(random() % contp->search_period);
            if (search) {
                if (contp->test_walk)
                    search = random() % (contp->test_order_stats ? 4 : 2);
                else
                    search = 1 + random() % (contp->test_order_stats ? 3 : 1);
                switch (search) {
                case 0:
                    ret = auto_test_walk(contctx, key, 1, 1);
                    break;
                case 1:
                    if (contp->test_range_search && (random() % 2 == 0))
                        ret = auto_test_range_search(contctx, key, 1, 1);
                    else
                        ret = auto_test_search(contctx, key, 1, 1);
                    break;
                case 2:
                    ret = auto_test_select(contctx, key, 1, 1);
                    break;
                case 3:
                    ret = auto_test_get_index(contctx, key, 1, 1);
                    break;
                default:
                    ret = -EIO;
                    goto end;
                }
                if (ERROR_FATAL(ret))
                    break;
                if (!(contp->verify_after_search))
                    verify = 0;
            } else {
                delete = bitmap_get(bmdata->bitmap, key);
                if (!delete) {
                    VERBOSE_LOG(log, "ins %d\n", key);
                    ret = auto_test_insert(contctx, key, 0, 1, 1, 0, 0,
                                           contp->confirm);
                    if (ERROR_FATAL(ret))
                        break;
                    if ((ret == -ENOSPC) && contp->empty_on_fill) {
                        ret = empty_container(contctx);
                        if (ret != 0)
                            break;
                    } else if (ret == 2)
                        verify = 1;
                    VERBOSE_LOG(stderr, "inserted %d\n"
                        "--------------------------------------------------"
                        "\n", key);
                } else if (PERFORM_REPLACE(contp)) {
                    VERBOSE_LOG(log, "upd %d\n", key);
                    ret = auto_test_insert(contctx, key, 1, 1, 1, 0, 0,
                                           contp->confirm);
                    if (ERROR_FATAL(ret))
                        break;
                    if ((ret == -ENOSPC) && contp->empty_on_fill) {
                        ret = empty_container(contctx);
                        if (ret != 0)
                            break;
                    } else if (ret == 2)
                        verify = 1;
                    VERBOSE_LOG(stderr, "replaced %d\n"
                        "--------------------------------------------------"
                        "\n", key);
                } else {
                    VERBOSE_LOG(log, "del %d\n", key);
                    ret = auto_test_delete(contctx, key, 1, 1, 0,
                                           contp->confirm);
                    if (ERROR_FATAL(ret))
                        break;
                    if (ret == 2)
                        verify = 1;
                    VERBOSE_LOG(stderr, "deleted %d\n"
                        "--------------------------------------------------"
                        "\n",
                        key);
                }
            }
        }

        if (contp->verify
            && ((verify == 1) || !(random() % contp->verification_period))) {
            ret = (*(contctx->cb.verify_rand))(contctx);
            if (ret != 0)
                break;
        } else
            ret = 0;

        if (contp->verbose_stats)
            refresh_stat_output(contctx);
    }

end:

    if (perf_cmp_hdl != NULL)
        perf_cmp_finish(perf_cmp_hdl);

    if (contctx->cb.end_test != NULL) {
        tmp = (*(contctx->cb.end_test))(contctx);
        if (tmp != 0)
            ret = tmp;
    }

    restore_default_handler(SIGINT);
    restore_default_handler(SIGTERM);
    restore_default_handler(SIGUSR1);
    restore_default_handler(SIGUSR2);

    return ret;
}

int
cont_test_fill_drain(struct cont_ctx *contctx,
                     const struct cont_params *contp, FILE *log)
{
    int drain = 0;
    int err_test_old;
    int n = 0;
    int ret = 0, tmp;
    struct avl_tree *key_set;
    uint64_t seed[256/sizeof(uint64_t)];

    if ((set_signal_handler(SIGINT, &lib_term_handler) == -1)
        || (set_signal_handler(SIGTERM, &lib_term_handler) == -1)
        || (set_signal_handler(SIGHUP, &pipe_handler) == -1)
        || (set_signal_handler(SIGPIPE, &pipe_handler) == -1)
        || (set_signal_handler(SIGUSR1, &usr1_handler) == -1)
        || (set_signal_handler(SIGUSR2, &usr2_handler) == -1)) {
        ret = -errno;
        error(0, errno, "Couldn't set signal handler");
        return ret;
    }

    DISABLE_ERR_TEST(err_test_old);
    ret = avl_tree_new(&key_set, sizeof(int), &int_key_cmp, 0, NULL, NULL,
                       NULL);
    ENABLE_ERR_TEST(err_test_old);
    if (ret != 0) {
        error(0, -ret, "Error");
        goto end1;
    }

    init_shuffle((long *)seed, sizeof(seed));

    while (!quit && (NUM_OPS(contctx) < contp->num_ops)) {
        int key;
        int verify = -1;

        ret = handle_usr_signals(contctx, NULL, NULL);
        if (ret != 0)
            break;

        if (!drain) {
            key = (int)shuffle(log_2_pow2(contp->max_key), n, seed,
                               ARRAY_SIZE(seed));
            if (key == -1) {
                error(0, 0, "Key range must be an even power of 2");
                ret = -EINVAL;
                break;
            }
            VERBOSE_LOG(log, "ins %d\n", key);
            ret = auto_test_insert(contctx, key, 0, 1, 1, 0, 1, contp->confirm);
            if (ERROR_FATAL(ret))
                break;
            if (ret == 0) {
                DISABLE_ERR_TEST(err_test_old);
                ret = avl_tree_insert(key_set, &key);
                ENABLE_ERR_TEST(err_test_old);
                if (ret != 0)
                    break;
                ++n;
                if (n == contp->max_key)
                    drain = 1;
            } else if ((ret == -ENOSPC) && (n > 0))
                drain = 1;
            else if (ret == 2)
                verify = 1;
            VERBOSE_LOG(stderr, "inserted %d\n"
                "--------------------------------------------------"
                "\n",
                key);
        } else {
            DISABLE_ERR_TEST(err_test_old);
            ret = avl_tree_select(key_set, random() % n, &key);
            ENABLE_ERR_TEST(err_test_old);
            if (ret != 1)
                break;
            VERBOSE_LOG(log, "del %d\n", key);
            ret = auto_test_delete(contctx, key, 1, 1, 1, contp->confirm);
            if (ERROR_FATAL(ret))
                break;
            if (ret == 0) {
                ret = avl_tree_delete(key_set, &key);
                if (ret != 0)
                    break;
                --n;
                if (n == 0) {
                    drain = 0;
                    init_shuffle((long *)seed, sizeof(seed));
                }
            } else if (ret == 2)
                verify = 1;
            VERBOSE_LOG(stderr, "deleted %d\n"
                "--------------------------------------------------"
                "\n",
                key);
        }

        if (contp->dump) {
            ret = (*(contctx->ops.dump))(stdout, contctx->cont);
            if (ret != 0) {
                error(0, -ret, "Error dumping container");
                goto end2;
            }
        }

        if (contp->verify
            && ((verify == 1) || !(random() % contp->verification_period))) {
            ret = (*(contctx->cb.verify_rand))(contctx);
            if (ret != 0)
                break;
        } else
            ret = 0;

        if (contp->verbose_stats)
            refresh_stat_output(contctx);
    }

    avl_tree_free(key_set);

end2:
    if (contctx->cb.end_test != NULL) {
        tmp = (*(contctx->cb.end_test))(contctx);
        if (tmp != 0)
            ret = tmp;
    }
end1:
    restore_default_handler(SIGINT);
    restore_default_handler(SIGTERM);
    restore_default_handler(SIGUSR1);
    restore_default_handler(SIGUSR2);
    return ret;
}

int
cont_test_fill_drain_sorted(struct cont_ctx *contctx,
                            const struct cont_params *contp, FILE *log)
{
    int drain = 0;
    int n = 0;
    int ret = 0, tmp;

    if ((set_signal_handler(SIGINT, &lib_term_handler) == -1)
        || (set_signal_handler(SIGTERM, &lib_term_handler) == -1)
        || (set_signal_handler(SIGHUP, &pipe_handler) == -1)
        || (set_signal_handler(SIGPIPE, &pipe_handler) == -1)
        || (set_signal_handler(SIGUSR1, &usr1_handler) == -1)
        || (set_signal_handler(SIGUSR2, &usr2_handler) == -1)) {
        ret = -errno;
        error(0, errno, "Couldn't set signal handler");
        return ret;
    }

    while (!quit && (NUM_OPS(contctx) < contp->num_ops)) {
        int key;
        int verify = -1;

        ret = handle_usr_signals(contctx, NULL, NULL);
        if (ret != 0)
            break;

        if (!drain) {
            key = n;
            VERBOSE_LOG(log, "ins %d\n", key);
            ret = auto_test_insert(contctx, key, 0, 1, 1, 0, 1, contp->confirm);
            if (ERROR_FATAL(ret))
                break;
            if (ret == 0) {
                ++n;
                if (n == contp->max_key)
                    drain = 1;
            } else if ((ret == -ENOSPC) && (n > 0))
                drain = 1;
            else if (ret == 2)
                verify = 1;
            VERBOSE_LOG(stderr, "inserted %d\n"
                "--------------------------------------------------"
                "\n",
                key);
        } else {
            key = n;
            VERBOSE_LOG(log, "del %d\n", key);
            ret = auto_test_delete(contctx, key, 1, 1, 1, contp->confirm);
            if (ERROR_FATAL(ret))
                break;
            if (ret == 0) {
                if (n == 0)
                    drain = 0;
                else
                    --n;
            } else if (ret == 2)
                verify = 1;
            VERBOSE_LOG(stderr, "deleted %d\n"
                "--------------------------------------------------"
                "\n",
                key);
        }

        if (contp->dump) {
            ret = (*(contctx->ops.dump))(stdout, contctx->cont);
            if (ret != 0) {
                error(0, -ret, "Error dumping container");
                goto end;
            }
        }

        if (contp->verify
            && ((verify == 1) || !(random() % contp->verification_period))) {
            ret = (*(contctx->cb.verify_rand))(contctx);
            if (ret != 0)
                break;
        } else
            ret = 0;

        if (contp->verbose_stats)
            refresh_stat_output(contctx);
    }

end:
    if (contctx->cb.end_test != NULL) {
        tmp = (*(contctx->cb.end_test))(contctx);
        if (tmp != 0)
            ret = tmp;
    }
    restore_default_handler(SIGINT);
    restore_default_handler(SIGTERM);
    restore_default_handler(SIGUSR1);
    restore_default_handler(SIGUSR2);
    return ret;
}

void __attribute__((constructor))
ctor()
{
    const char *confpath;
    int err;

    confpath = getenv(CONFIG_PATH_ENV);
    if (confpath == NULL)
        confpath = DEFAULT_CONFIG_PATH;

    err = parse_config(confpath, &params);
    if (err)
        error(0, -err, "Error parsing configuration");

    print_config(stderr, &params);
}

/* vi: set expandtab sw=4 ts=4: */