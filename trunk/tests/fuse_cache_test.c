/*
 * fuse_cache_test.c
 */

#include "back_end.h"
#include "back_end_dbm.h"
#include "common.h"
#include "fuse_cache.h"
#include "test_util_back_end.h"
#include "util.h"
#include "util_test_common.h"

#include <bitmap.h>

#include <files/acc_ctl.h>

#include <test_util.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <paths.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

struct test_opts {
    struct be_test_opts testopts;
    int                 *test_type;
    uint32_t            *max_data_len;
};

struct params {
    struct be_params    bep;
    const char          *bitmap;
    const char          *file;
    uint32_t            max_data_len;
};

struct cache_bitmap_data {
    struct be_bitmap_data   bmdata;
    int                     loaded;
};

struct fuse_cache_ctx {
    struct be_ctx   bectx;
    struct back_end *be;
    const char      *bitmap;
    uint32_t        max_data_len;
};

struct cache_data {
    size_t      len;
    uint64_t    data[1];
};

struct fn2_ctx {
    unsigned    key_size;
    unsigned    keys_found;
    int         prevkey;
};

struct fn3_ctx {
    struct bitmap_data  *bmdata;
    int                 bitmap_pos;
    unsigned            key_size;
    unsigned            keys_found;
    int                 prevkey;
};

struct walk_ctx {
    int                     (*fn)(const void *, void *);
    void                    *ctx;
    struct fuse_cache_ctx   *cachectx;
};

#define FUSE_CACHE_TEST_TMPDIR "fuse_cache_test_XXXXXX"

#define FUSE_CACHE_LOG_PREFIX _PATH_TMP "fuse_cache_log_"

#define MAX_DATA_LEN (128 * 1024)

#define DATA_LEN(len) (offsetof(struct cache_data, data) + len)

static int fuse_cache_verbose_debug;

static FILE *testlog;

static int key_size;

static int parse_test_opt(int, void *);
static int parse_cmdline(int, char **, int *, struct params *, int *,
                         uint32_t *);

static int int_cmp(const void *, const void *, void *);

static void sync_cb(int, void *);
static void set_trans_cb(void *, void (*)(int, int, int, void *), void *);

static int check_increasing(int *, int);

static int fn2(const void *, const void *, size_t, void *);
static int fn3(const void *, const void *, size_t, void *);

static int load_bitmap(const char *, struct be_stats *, struct bitmap_data *);
static int alloc_bitmap(const char *, struct bitmap_data *);
static int save_bitmap(const char *, struct be_stats *, struct bitmap_data *);

static int do_back_end_create(struct fuse_cache_ctx *, const char *);
static int do_back_end_open(struct fuse_cache_ctx *, const char *);

static int init_fuse_cache_ctx(struct fuse_cache_ctx *, const char *, uint32_t,
                               const char *, struct cache_bitmap_data *, int,
                               int);
static int destroy_fuse_cache_ctx(struct fuse_cache_ctx *);

static void set_int_array(int *, size_t, int);
static int check_int_array(const int *, size_t, int);

static int walk_cb(const void *, const void *, size_t, void *);

static int test_insert(void *, void *);
static int test_replace(void *, void *);
static int test_search(void *, void *, void *);
static int test_delete(void *, void *);
static int test_walk(void *, void *, int (*)(const void *, void *), void *);
static int test_iter_new(void **, void *);
static int test_iter_free(void *);
static int test_iter_get(void *, void *);
static int test_iter_next(void *);
static int test_iter_search(void *, const void *);
static int test_trans_new(void *);
static int test_trans_abort(void *);
static int test_trans_commit(void *);
static int test_dump(FILE *, void *);

static int do_walk(void *, int (*)(const void *, const void *, size_t, void *),
                   void *);

static int walk_cache(struct fuse_cache_ctx *);

static int verify_rand(struct be_ctx *);
static int print_stats(FILE *, struct be_ctx *, int);
static int do_end_test(struct be_ctx *);

static int run_automated_test(int, const struct params *);

static int
parse_test_opt(int opt, void *test_opts)
{
    struct test_opts *testopts = test_opts;

    switch (opt) {
    case 'B':
        *testopts->test_type = 5;
        break;
    case 'K':
        *testopts->max_data_len = strtoumax(optarg, NULL, 10);
        break;
    case 'z':
        *testopts->test_type = 4;
        break;
    default:
        return -1;
    }

    return 0;
}

static int
parse_cmdline(int argc, char **argv, int *seed, struct params *p,
              int *test_type, uint32_t *max_data_len)
{
    struct test_opts testopts = {
        .test_type      = test_type,
        .max_data_len   = max_data_len
    };

    static const char progusage[] = {
        "    -B         delete only inserted keys and vice versa (consult "
        "bitmap when\n"
        "               choosing keys)\n"
        "    -K SIZE    generate data with length no greater than the given "
        "size in bytes\n"
        "    -z         run test with sorted insertions and deletions\n"
    };

    return parse_be_test_cmdline(argc, argv, progusage, "BK:z", &parse_test_opt,
                                 (struct be_params *)p,
                                 (struct be_test_opts *)&testopts, seed, NULL,
                                 NULL, NULL, 0);
}

static int
int_cmp(const void *k1, const void *k2, void *key_ctx)
{
    if (key_ctx != NULL) {
        struct db_key_ctx *ctx = key_ctx;

        memcpy(ctx->last_key, k2, sizeof(int));
        ctx->last_key_valid = 1;
    }

    return int_key_cmp(k1, k2, (void *)(intptr_t)key_size);
}

static void
sync_cb(int status, void *ctx)
{
    (void)status;
    (void)ctx;

    return;
}

static void
set_trans_cb(void *args, void (*cb)(int, int, int, void *), void *ctx)
{
    struct db_args *dbargs = args;

    dbargs->trans_cb = cb;
    dbargs->trans_ctx = ctx;
}

static int
check_increasing(int *prev, int curr)
{
    if (curr <= *prev) {
        error(0, 0, "curr <= prev during walk (%d <= %d)", curr, *prev);
        return -1;
    }

    return 0;
}

static int
fn2(const void *key, const void *data, size_t datalen, void *ctx)
{
    const struct cache_data *d = data;
    int curr;
    struct fn2_ctx *wctx = ctx;

    curr = get_short_key(key, wctx->key_size);

    if (datalen != DATA_LEN(d->len)
        || check_int_array((const int *)d->data, d->len / sizeof(int), curr)
           != 0) {
        errmsgf("Data (length %zu) for key %d corrupt\n", datalen,
                *(const int *)key);
        return -EIO;
    }

    ++wctx->keys_found;
    if (check_increasing(&wctx->prevkey, curr) == -1)
        return -1;

    printf("%d\n", curr);

    return 0;
}

static int
fn3(const void *key, const void *data, size_t datalen, void *ctx)
{
    const struct cache_data *d = data;
    int curr;
    struct fn3_ctx *wctx = ctx;
    unsigned res;

    curr = get_short_key(key, wctx->key_size);

    if (datalen != DATA_LEN(d->len)
        || check_int_array((const int *)d->data, d->len / sizeof(int), curr)
           != 0) {
        errmsgf("Data (length %zu) for key %d corrupt\n", datalen,
                *(const int *)key);
        return -EIO;
    }

    ++wctx->keys_found;
    if (check_increasing(&wctx->prevkey, curr) == -1) {
        if (wctx->keys_found > 1)
            infochr('\n');
        return -EIO;
    }

    if (bitmap_find_next_set(wctx->bmdata->bitmap, wctx->bmdata->bitmap_len,
                             wctx->bitmap_pos, &res, 1)
        == 0
        || curr != (wctx->bitmap_pos = res)) {
        errmsgf("%sBitmap (%6d) and database (%6d) differ\n",
                wctx->keys_found > 1 ? "\n" : "", wctx->bitmap_pos, curr);
        return -EIO;
    }

    infomsgf("\rBitmap and cache agree up to %6d", wctx->bitmap_pos);

    ++wctx->bitmap_pos;

    return 0;
}

static int
load_bitmap(const char *file, struct be_stats *stats,
            struct bitmap_data *bmdata)
{
    const char *errmsg = NULL;
    int err;
    int fd;
    size_t bmsize;
    struct stat s;

    bmsize = bmdata->bitmap_len * sizeof(*bmdata->bitmap);

    fd = open(file, O_RDONLY);
    if (fd == -1) {
        err = ERRNO;
        errmsg = "Couldn't open bitmap file";
        goto err1;
    }

    if (fstat(fd, &s) == -1) {
        errmsg = "Couldn't get status of bitmap file";
        goto err3;
    }
    if (s.st_size != (off_t)(sizeof(struct be_stats) + bmsize)) {
        err = EILSEQ;
        errmsg = "Bitmap has incorrect size";
        goto err2;
    }

    if (do_read(fd, stats, sizeof(struct be_stats), 4096)
        != sizeof(struct be_stats)
        || do_read(fd, bmdata->bitmap, bmsize, 4096) != bmsize) {
        err = errno == 0 ? EILSEQ : ERRNO;
        errmsg = "Couldn't read bitmap file";
        goto err2;
    }
    infomsgf("Loaded verification bitmap from %s\n", file);

    close(fd);

    return 0;

err3:
    err = ERRNO;
err2:
    close(fd);
err1:
    error(0, err, "%s", errmsg);
    errno = err;
    return -1;
}

static int
alloc_bitmap(const char *file, struct bitmap_data *bmdata)
{
    const char *errmsg = NULL;
    int err;
    int fd;
    size_t totsize;

    fd = open(file, O_CREAT | O_WRONLY, ACC_MODE_DEFAULT);
    if (fd == -1) {
        err = ERRNO;
        errmsg = "Couldn't open bitmap file";
        goto err1;
    }

    totsize = sizeof(struct be_stats)
              + bmdata->bitmap_len * sizeof(*bmdata->bitmap);

    err = falloc(fd, 0, totsize);
    if (err) {
        errmsg = "Error allocating space for bitmap file";
        goto err2;
    }

    if (ftruncate(fd, totsize) == -1) {
        errmsg = "Error extending bitmap file";
        goto err3;
    }

    close(fd);

    return 0;

err3:
    err = ERRNO;
err2:
    close(fd);
err1:
    error(0, err, "%s", errmsg);
    errno = err;
    return -1;
}

static int
save_bitmap(const char *file, struct be_stats *stats,
            struct bitmap_data *bmdata)
{
    const char *errmsg = NULL;
    int err;
    int fd;
    size_t bmsize;

    bmsize = bmdata->bitmap_len * sizeof(*bmdata->bitmap);

    fd = open(file, O_WRONLY);
    if (fd == -1) {
        err = ERRNO;
        errmsg = "Couldn't open bitmap file";
        goto err1;
    }

    if (do_write(fd, stats, sizeof(struct be_stats), 4096)
        != sizeof(struct be_stats)
        || do_write(fd, bmdata->bitmap, bmsize, 4096) != bmsize
        || fsync(fd) == -1) {
        errmsg = "Couldn't write bitmap file";
        goto err2;
    }
    infomsgf("Saved verification bitmap to %s\n", file);

    close(fd);

    return 0;

err2:
    err = ERRNO;
    close(fd);
err1:
    error(0, err, "%s", errmsg);
    errno = err;
    return -1;
}

static int
do_back_end_create(struct fuse_cache_ctx *cachectx, const char *file)
{
    struct db_args dbargs;
    struct fuse_cache_args args;

    key_size = cachectx->bectx.key_size;

    dbargs.db_pathname = file;
    dbargs.db_mode = ACC_MODE_DEFAULT;
    dbargs.ro = 0;
    dbargs.sync_cb = &sync_cb;
    dbargs.sync_ctx = cachectx;

    args.ops = BACK_END_DBM;
    args.set_trans_cb = &set_trans_cb;
    args.disable_iter_commit = &back_end_dbm_disable_iter_commit;
    args.sync_cb = &sync_cb;
    args.sync_ctx = cachectx;
    args.args = &dbargs;

    return back_end_create(&cachectx->be, key_size, BACK_END_FUSE_CACHE,
                           &int_cmp, &args);
}

static int
do_back_end_open(struct fuse_cache_ctx *cachectx, const char *file)
{
    struct db_args dbargs;
    struct fuse_cache_args args;

    key_size = cachectx->bectx.key_size;

    dbargs.db_pathname = file;
    dbargs.db_mode = ACC_MODE_DEFAULT;
    dbargs.ro = 0;
    dbargs.sync_cb = &sync_cb;
    dbargs.sync_ctx = cachectx;

    args.ops = BACK_END_DBM;
    args.set_trans_cb = &set_trans_cb;
    args.disable_iter_commit = &back_end_dbm_disable_iter_commit;
    args.sync_cb = &sync_cb;
    args.sync_ctx = cachectx;
    args.args = &dbargs;

    return back_end_open(&cachectx->be, key_size, BACK_END_FUSE_CACHE,
                         &int_cmp, &args);
}

static int
init_fuse_cache_ctx(struct fuse_cache_ctx *cachectx, const char *file,
                    uint32_t max_data_len, const char *bitmap,
                    struct cache_bitmap_data *bmdata, int key_size, int max_key)
{
    int ret;

    init_be_ctx((struct be_ctx *)cachectx, bmdata, key_size, max_key);

    cachectx->bitmap = bitmap;

    cachectx->max_data_len = max_data_len == 0
                             ? MAX_DATA_LEN
                             : MIN(max_data_len, MAX_DATA_LEN);

    if (access(bitmap, F_OK) == -1) {
        if (errno != ENOENT) {
            ret = MINUS_ERRNO;
            error(0, errno, "Couldn't access bitmap file");
            return ret;
        }
    } else {
        if (load_bitmap(bitmap, &cachectx->bectx.stats, &bmdata->bmdata.bmdata)
            == -1)
            return MINUS_ERRNO;
        bmdata->loaded = 1;
    }
    if (access(file, F_OK) == -1) {
        if (errno != ENOENT) {
            ret = MINUS_ERRNO;
            error(0, errno, "Couldn't access database file");
            return ret;
        }
        if (bmdata->loaded) {
            ret = -ENOENT;
            error(0, 0, "Bitmap file present but database file missing");
            return ret;
        }
        ret = change_to_tmpdir(FUSE_CACHE_TEST_TMPDIR);
        if (ret != 0)
            return ret;
        if (alloc_bitmap(bitmap, &bmdata->bmdata.bmdata) == -1)
            return MINUS_ERRNO;
        ret = do_back_end_create(cachectx, file);
        if (ret != 0)
            goto err;
    } else {
        if (!bmdata->loaded) {
            ret = -ENOENT;
            error(0, 0, "Database file present but bitmap file missing");
            return ret;
        }
        ret = do_back_end_open(cachectx, file);
        if (ret != 0)
            goto err;
    }

    cachectx->bectx.be = cachectx;

    SET_STD_OPS(cachectx->bectx, test);
    SET_STD_ITER_OPS_NO_PREV(cachectx->bectx, test);
    SET_REPLACE_OP(cachectx->bectx, test);
    SET_WALK_OP(cachectx->bectx, test);
    SET_TRANS_OPS(cachectx->bectx, test);
    cachectx->bectx.cb.verify_rand = &verify_rand;
    cachectx->bectx.cb.print_stats = &print_stats;
    cachectx->bectx.cb.end_test = &do_end_test;

    return 0;

err:
    error(0, -ret, "Couldn't open database");
    return ret;
}

static int
destroy_fuse_cache_ctx(struct fuse_cache_ctx *cachectx)
{
    struct back_end *be = cachectx->be;

    back_end_close(be);

    return 0;
}

static void
set_int_array(int *arr, size_t len, int val)
{
    size_t i;

    for (i = 0; i < len; i++)
        arr[i] = val;
}

static int
check_int_array(const int *arr, size_t len, int val)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (arr[i] != val)
            return -1;
    }

    return 0;
}

static int
walk_cb(const void *key, const void *data, size_t datasize, void *ctx)
{
    struct walk_ctx *walkctx = ctx;

    (void)data;
    (void)datasize;

    return (*walkctx->fn)(key, walkctx->ctx);
}

static int
test_insert(void *be, void *key)
{
    int err;
    int k;
    size_t len, totlen;
    struct cache_data *data;
    struct fuse_cache_ctx *cachectx = be;

    k = *(int *)key;

    len = 1 + random() % (cachectx->max_data_len / sizeof(int));
    totlen = len * sizeof(int);
    data = do_malloc(DATA_LEN(totlen));
    if (data == NULL)
        return MINUS_ERRNO;
    data->len = totlen;
    totlen = DATA_LEN(totlen);
    set_int_array((int *)data->data, len, k);

    err = back_end_insert(cachectx->be, key, data, totlen);
    free(data);

    return err;
}

static int
test_replace(void *be, void *key)
{
    int k;
    int ret;
    size_t len, totlen;
    struct cache_data *data;
    struct fuse_cache_ctx *cachectx = be;

    k = *(int *)key;

    len = 1 + random() % (cachectx->max_data_len / sizeof(int));
    totlen = len * sizeof(int);
    data = do_malloc(DATA_LEN(totlen));
    if (data == NULL)
        return MINUS_ERRNO;
    data->len = totlen;
    totlen = DATA_LEN(totlen);
    set_int_array((int *)data->data, len, k);

    ret = back_end_replace(cachectx->be, key, data, totlen);
    free(data);

    return ret;
}

static int
test_search(void *be, void *key, void *res)
{
    int ret;
    size_t datalen;
    struct cache_data *data;
    struct fuse_cache_ctx *cachectx = be;

    ret = back_end_look_up(cachectx->be, key, NULL, NULL, &datalen, 0);
    if (ret != 1)
        return ret;

    data = do_malloc(datalen);
    if (data == NULL)
        return MINUS_ERRNO;

    ret = back_end_look_up(cachectx->be, key, res, data, &datalen, 0);
    if ((ret == 1
         && check_int_array((const int *)data->data, data->len / sizeof(int),
                            *(int *)res)
            != 0)
        || ret == 0)
        ret = -EIO;

    free(data);

    return ret;
}

static int
test_delete(void *be, void *key)
{
    struct fuse_cache_ctx *cachectx = be;

    return back_end_delete(cachectx->be, key);
}

static int
test_walk(void *be, void *startkey, int (*fn)(const void *, void *), void *ctx)
{
    struct fuse_cache_ctx *cachectx = be;
    struct walk_ctx walkctx;

    (void)startkey;

    walkctx.fn = fn;
    walkctx.ctx = ctx;
    walkctx.cachectx = cachectx;

    return back_end_walk(cachectx->be, &walk_cb, &walkctx);
}

static int
test_iter_new(void **iter, void *be)
{
    struct fuse_cache_ctx *cachectx = be;

    return back_end_iter_new((struct back_end_iter **)iter, cachectx->be);
}

static int
test_iter_free(void *iter)
{
    return back_end_iter_free(iter);
}

static int
test_iter_get(void *iter, void *ret)
{
    int err;
    size_t datalen;
    struct cache_data *data;

    err = back_end_iter_get(iter, NULL, NULL, &datalen);
    if (err)
        return err;

    data = do_malloc(datalen);
    if (data == NULL)
        return MINUS_ERRNO;

    err = back_end_iter_get(iter, ret, data, &datalen);
    if (!err
        && check_int_array((const int *)data->data, data->len / sizeof(int),
                           *(int *)ret)
           != 0)
        err = -EIO;

    free(data);

    return err;
}

static int
test_iter_next(void *iter)
{
    return back_end_iter_next(iter);
}

static int
test_iter_search(void *iter, const void *key)
{
    return back_end_iter_search(iter, key);
}

static int
test_trans_new(void *be)
{
    struct fuse_cache_ctx *cachectx = be;

    return back_end_trans_new(cachectx->be);
}

static int
test_trans_abort(void *be)
{
    struct fuse_cache_ctx *cachectx = be;

    return back_end_trans_abort(cachectx->be);
}

static int
test_trans_commit(void *be)
{
    struct fuse_cache_ctx *cachectx = be;

    return back_end_trans_commit(cachectx->be);
}

static int
test_dump(FILE *f, void *be)
{
    (void)f;
    (void)be;

    return 0;
}

static int
do_walk(void *be, int (*fn)(const void *, const void *, size_t, void *),
        void *ctx)
{
    struct fuse_cache_ctx *cachectx = be;

    return back_end_walk(cachectx->be, fn, ctx);
}

static int
walk_cache(struct fuse_cache_ctx *cachectx)
{
    int ret;
    struct fn2_ctx data = {
        .key_size       = cachectx->bectx.key_size,
        .prevkey        = -1,
        .keys_found     = 0
    };

    while ((ret = do_walk(cachectx->bectx.be, &fn2, &data)) == 1)
        ;
    /* XXX */
    if (ret != 0)
        error(0, -ret, "Error walking database");

    return ret;
}

static int
verify_rand(struct be_ctx *bectx)
{
    int ret;
    struct bitmap_data *bmdata = bectx->bmdata;
    struct fuse_cache_ctx *cachectx;
    struct fn3_ctx data;
    unsigned res;

    cachectx = bectx->be;

    if (mprotect(bmdata->bitmap, bmdata->bitmap_len * sizeof(unsigned),
                 PROT_READ) == -1) {
        ret = MINUS_ERRNO;
        error(0, errno, "Couldn't set memory protection");
        return ret;
    }

    data.bmdata = bmdata;
    data.bitmap_pos = 0;
    data.key_size = bectx->key_size;
    data.keys_found = 0;
    data.prevkey = -1;

    while ((ret = do_walk(cachectx, &fn3, &data)) == 1)
        ;
    if (ret != 0) {
        error(0, -ret, "Error walking database");
        goto end;
    }
    if (data.keys_found > 0)
        infochr('\n');

    if (bitmap_find_next_set(data.bmdata->bitmap, data.bmdata->bitmap_len,
                             data.bitmap_pos, &res, 1)
        != 0) {
        errmsg("Bitmap and cache differ\n");
        data.bitmap_pos = res;
        ret = -EIO;
    }

end:
    mprotect(bmdata->bitmap, bmdata->bitmap_len * sizeof(unsigned),
             PROT_READ | PROT_WRITE);
    return ret;
}

static int
print_stats(FILE *f, struct be_ctx *bectx, int times)
{
    struct be_stats *cstats;

    (void)bectx;
    (void)times;

    cstats = &bectx->stats;

    fprintf(f, "%12" PRIu64 " repeat insert%s\n"
            "%12" PRIu64 " repeat delete%s\n"
            "%12" PRIu64 " operation%s\n"
            "%12" PRIu64 " out-of-range operation%s\n"
            "%12" PRIu64 " key%s generated\n"
            "%12" PRIu32 " key%s in database\n"
            "key size %d bytes\n",
            INT_OUTPUT(cstats->repeat_inserts, 0),
            INT_OUTPUT(cstats->repeat_deletes, 0),
            INT_OUTPUT(cstats->num_ops, 0),
            INT_OUTPUT(cstats->num_ops_out_of_range, 0),
            INT_OUTPUT(cstats->num_gen, 0),
            INT_OUTPUT(cstats->num_keys, 0),
            bectx->key_size);

    return 0;
}

static int
do_end_test(struct be_ctx *bectx)
{
    struct fuse_cache_ctx *cachectx = bectx->be;

    if (cachectx->bectx.bmdata) {
        return save_bitmap(cachectx->bitmap, &cachectx->bectx.stats,
                           cachectx->bectx.bmdata);
    }

    return 0;
}

static int
run_automated_test(int test_type, const struct params *p)
{
    const struct be_params *bep = &p->bep;
    int ret, tmp;
    struct be_ctx *bectx;
    struct cache_bitmap_data bmdata;
    struct fuse_cache_ctx cachectx;

    ret = init_bitmap(&bmdata.bmdata.bmdata, bep->max_key);
    if (ret != 0)
        goto bitmap_err;
    ret = init_bitmap(&bmdata.bmdata.bmdata_saved, bep->max_key);
    if (ret != 0) {
        free_bitmap(&bmdata.bmdata.bmdata);
        goto bitmap_err;
    }
    bmdata.loaded = 0;

    ret = init_fuse_cache_ctx(&cachectx, p->file, p->max_data_len, p->bitmap,
                              &bmdata, bep->key_size, bep->max_key);
    if (ret != 0)
        goto end1;

    bectx = (struct be_ctx *)&cachectx;

    if (fuse_cache_verbose_debug && open_log_file(0) == NULL)
        goto end1;

    switch (test_type) {
    case 3:
        ret = be_test_rand_repeat(bectx, bep, testlog);
        break;
    case 4:
        ret = be_test_sorted(bectx, bep, testlog);
        break;
    case 5:
        ret = be_test_rand_norepeat(bectx, bep, testlog);
        break;
    default:
        ret = -EIO;
    }

    if (ret != 0)
        goto end2;

    switch (test_type) {
    case 3:
    case 4:
        if (bep->use_be)
            ret = bep->use_bitmap ? verify_rand(bectx) : walk_cache(&cachectx);
        else if (bep->use_bitmap)
            print_bitmap(stdout, cachectx.bectx.bmdata);
        break;
    case 5:
        ret = verify_rand(bectx);
        break;
    default:
        ret = -EIO;
    }

    if (ret != -EIO) {
        tmp = destroy_fuse_cache_ctx(&cachectx);
        if (ret == 0)
            ret = tmp;
    }

end2:
    close_log_file(NULL);
end1:
    free_bitmap(&bmdata.bmdata.bmdata);
    free_bitmap(&bmdata.bmdata.bmdata_saved);
    return ret ? -1 : 0;

bitmap_err:
    error(0, -ret, "Error initializing test bitmap");
    return -1;
}

int
main(int argc, char **argv)
{
    int ret;
    int seed = get_seed();
    int test_type = 3;

    static struct params p = {
        .bep = {
            .insert_ratio           = 4,
            .key_size               = sizeof(int),
            .max_key                = 128 * 1024,
            .num_ops                = ULLONG_MAX,
            .search_period          = 128,
            .verification_period    = 1024 * 1024,
            .test_replace           = 1,
            .test_iter              = 1,
            .use_bitmap             = 1,
            .use_be                 = 1,
            .zero_keys              = 1
        },
        .bitmap = "bitmap_fuse_cache_test",
        .file   = "fs.db_test"
    };

    verbose_debug = &fuse_cache_verbose_debug;

    logprefix = FUSE_CACHE_LOG_PREFIX;
    testlogp = &testlog;

    ret = parse_cmdline(argc, argv, &seed, &p, &test_type, &p.max_data_len);
    if (ret != 0)
        return ret == -1 ? EXIT_FAILURE : EXIT_SUCCESS;

    if (init_test(argc, argv, seed, 0, 0, 0) == -1)
        return EXIT_FAILURE;

    ret = run_automated_test(test_type, &p);

    if (end_test(argc, argv, seed, ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE) != 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
