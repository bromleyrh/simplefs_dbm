/*
 * back_end_dbm.c
 */

#define _GNU_SOURCE

#include "back_end.h"
#include "back_end_dbm.h"
#include "util.h"

#include <dbm_high_level.h>

#include <files/util.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

struct db_ctx {
    struct dbh          *dbh;
    size_t              key_size;
    back_end_key_cmp_t  key_cmp;
    struct db_key_ctx   *key_ctx;
    void                (*trans_cb)(int, int, int, void *);
    void                *trans_ctx;
    void                (*sync_cb)(int, void *);
    void                *sync_ctx;
};

struct db_iter {
    db_hl_iter_t    iter;
    void            *srch_key;
    int             srch_status;
    struct db_ctx   *dbctx;
};

static void trans_cb(struct dbh *, int, int, int, void *);
static void sync_cb(struct dbh *, int, void *);

static int get_next_elem(void *, void *, size_t *, const void *,
                         struct db_ctx *);

static int back_end_dbm_create(void **, size_t, back_end_key_cmp_t, void *);
static int back_end_dbm_open(void **, size_t, back_end_key_cmp_t, void *);
static int back_end_dbm_close(void *);
static int back_end_dbm_insert(void *, const void *, const void *, size_t);
static int back_end_dbm_replace(void *, const void *, const void *, size_t);
static int back_end_dbm_look_up(void *, const void *, void *, void *, size_t *,
                                int);
static int back_end_dbm_delete(void *, const void *);
static int back_end_dbm_walk(void *, back_end_walk_cb_t, void *);
static int back_end_dbm_iter_new(void **, void *);
static int back_end_dbm_iter_free(void *);
static int back_end_dbm_iter_get(void *, void *, void *, size_t *);
static int back_end_dbm_iter_next(void *);
static int back_end_dbm_iter_search(void *, const void *);
static int back_end_dbm_trans_new(void *);
static int back_end_dbm_trans_abort(void *);
static int back_end_dbm_trans_commit(void *);
static int back_end_dbm_sync(void *);

const struct back_end_ops back_end_dbm_ops = {
    .create         = &back_end_dbm_create,
    .open           = &back_end_dbm_open,
    .close          = &back_end_dbm_close,
    .insert         = &back_end_dbm_insert,
    .replace        = &back_end_dbm_replace,
    .look_up        = &back_end_dbm_look_up,
    .delete         = &back_end_dbm_delete,
    .walk           = &back_end_dbm_walk,
    .iter_new       = &back_end_dbm_iter_new,
    .iter_free      = &back_end_dbm_iter_free,
    .iter_get       = &back_end_dbm_iter_get,
    .iter_next      = &back_end_dbm_iter_next,
    .iter_search    = &back_end_dbm_iter_search,
    .trans_new      = &back_end_dbm_trans_new,
    .trans_abort    = &back_end_dbm_trans_abort,
    .trans_commit   = &back_end_dbm_trans_commit,
    .sync           = &back_end_dbm_sync
};

static void
trans_cb(struct dbh *dbh, int trans_type, int act, int status, void *ctx)
{
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    (void)dbh;

    (*(dbctx->trans_cb))(trans_type, act, status, dbctx->trans_ctx);
}

static void
sync_cb(struct dbh *dbh, int status, void *ctx)
{
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    (void)dbh;

    (*(dbctx->sync_cb))(status, dbctx->sync_ctx);
}

static int
get_next_elem(void *retkey, void *retdata, size_t *retdatasize, const void *key,
              struct db_ctx *dbctx)
{
    db_hl_iter_t iter;
    int res;
    size_t datalen;

    if (retdatasize == NULL)
        retdatasize = &datalen;

    res = db_hl_iter_new(&iter, dbctx->dbh);
    if (res != 0)
        return res;

    res = db_hl_iter_search(iter, key);
    if (res != 1) {
        if (res == 0)
            res = -ENOENT;
        goto end;
    }

    res = db_hl_iter_next(iter);
    if (res != 0)
        goto end;

    res = db_hl_iter_get(iter, retkey, retdata, retdatasize);

end:
    db_hl_iter_free(iter);
    return res;
}

int
back_end_dbm_create(void **ctx, size_t key_size, back_end_key_cmp_t key_cmp,
                    void *args)
{
    int err;
    struct db_args *dbargs = (struct db_args *)args;
    struct db_ctx *ret;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;
    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    ret->key_ctx = do_malloc(sizeof(*(ret->key_ctx)));
    if (ret->key_ctx == NULL) {
        err = -errno;
        goto err1;
    }

    ret->key_ctx->last_key = do_malloc(key_size);
    if (ret->key_ctx->last_key == NULL) {
        err = -errno;
        goto err2;
    }
    ret->key_ctx->last_key_valid = 0;

    err = db_hl_create(&ret->dbh, dbargs->db_pathname, dbargs->db_mode,
                       key_size, (db_hl_key_cmp_t)key_cmp, ret->key_ctx, 0);
    if (err)
        goto err3;

    if (dbargs->trans_cb) {
        err = db_hl_set_cb(ret->dbh, &trans_cb, ret, NULL);
        if (err)
            goto err4;
        ret->trans_cb = dbargs->trans_cb;
        ret->trans_ctx = dbargs->trans_ctx;
    }
    if (dbargs->sync_cb) {
        err = db_hl_sync_set_cb(ret->dbh, &sync_cb, ret, NULL);
        if (err)
            goto err4;
        ret->sync_cb = dbargs->sync_cb;
        ret->sync_ctx = dbargs->sync_ctx;
    }

    *ctx = ret;
    return 0;

err4:
    db_hl_close(ret->dbh);
err3:
    free(ret->key_ctx->last_key);
err2:
    free(ret->key_ctx);
err1:
    free(ret);
    return err;
}

int
back_end_dbm_open(void **ctx, size_t key_size, back_end_key_cmp_t key_cmp,
                  void *args)
{
    char buf[PATH_MAX];
    const char *relpath;
    int dfd;
    int err;
    struct db_args *dbargs = (struct db_args *)args;
    struct db_ctx *ret;

    if (dirname_safe(dbargs->db_pathname, buf, sizeof(buf))
        == NULL)
        return -ENAMETOOLONG;
    dfd = open(buf, O_CLOEXEC | O_DIRECTORY | O_RDONLY);
    if (dfd == -1)
        return -errno;
    relpath = basename_safe(dbargs->db_pathname);

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL) {
        err = -errno;
        goto err1;
    }
    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    ret->key_ctx = do_malloc(sizeof(*(ret->key_ctx)));
    if (ret->key_ctx == NULL) {
        err = -errno;
        goto err2;
    }

    ret->key_ctx->last_key = do_malloc(key_size);
    if (ret->key_ctx->last_key == NULL) {
        err = -errno;
        goto err3;
    }
    ret->key_ctx->last_key_valid = 0;

    /* test for journal replay by attempting read-only open */
    err = db_hl_open(&ret->dbh, relpath, key_size, (db_hl_key_cmp_t)key_cmp,
                     ret->key_ctx, DB_HL_RDONLY | DB_HL_RELPATH, dfd);
    if (!(dbargs->ro)) {
        if (err) {
            if (err != -EROFS)
                goto err4;
            fputs("Replaying file system journal\n", stderr);
        } else {
            err = db_hl_close(ret->dbh);
            if (err)
                goto err4;
        }

        err = db_hl_open(&ret->dbh, relpath, key_size, (db_hl_key_cmp_t)key_cmp,
                         ret->key_ctx, DB_HL_RELPATH, dfd);
    }
    if (err)
        goto err4;

    if (dbargs->trans_cb) {
        err = db_hl_set_cb(ret->dbh, &trans_cb, ret, NULL);
        if (err)
            goto err4;
        ret->trans_cb = dbargs->trans_cb;
        ret->trans_ctx = dbargs->trans_ctx;
    }
    if (dbargs->sync_cb) {
        err = db_hl_sync_set_cb(ret->dbh, &sync_cb, ret, NULL);
        if (err)
            goto err5;
        ret->sync_cb = dbargs->sync_cb;
        ret->sync_ctx = dbargs->sync_ctx;
    }

    close(dfd);

    *ctx = ret;
    return 0;

err5:
    db_hl_close(ret->dbh);
err4:
    free(ret->key_ctx->last_key);
err3:
    free(ret->key_ctx);
err2:
    free(ret);
err1:
    close(dfd);
    return err;
}

int
back_end_dbm_close(void *ctx)
{
    int err;
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    err = db_hl_close(dbctx->dbh);

    free(dbctx->key_ctx->last_key);

    free(dbctx->key_ctx);

    free(dbctx);

    return err;
}

int
back_end_dbm_insert(void *ctx, const void *key, const void *data,
                    size_t datasize)
{
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    return db_hl_insert(dbctx->dbh, key, data, datasize);
}

int
back_end_dbm_replace(void *ctx, const void *key, const void *data,
                     size_t datasize)
{
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    return db_hl_replace(dbctx->dbh, key, data, datasize);
}

int
back_end_dbm_look_up(void *ctx, const void *key, void *retkey, void *retdata,
                     size_t *retdatasize, int look_up_nearest)
{
    int res;
    size_t datalen;
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    if (retdatasize == NULL)
        retdatasize = &datalen;

    dbctx->key_ctx->last_key_valid = 0;

    res = db_hl_search(dbctx->dbh, key, retkey, retdata, retdatasize);

    if (look_up_nearest && (res == 0) && dbctx->key_ctx->last_key_valid) {
        int cmp;

        cmp = (*(dbctx->key_cmp))(dbctx->key_ctx->last_key, key, NULL);
        if (cmp > 0) {
            res = db_hl_search(dbctx->dbh, dbctx->key_ctx->last_key, retkey,
                               retdata, retdatasize);
            assert(res != 0);
            return (res == 1) ? 0 : res;
        }
        res = get_next_elem(retkey, retdata, retdatasize,
                            dbctx->key_ctx->last_key, dbctx);
        return (res == -EADDRNOTAVAIL) ? 0: res;
    }

    return res;
}

int
back_end_dbm_delete(void *ctx, const void *key)
{
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    return db_hl_delete(dbctx->dbh, key);
}

int
back_end_dbm_walk(void *ctx, back_end_walk_cb_t fn, void *wctx)
{
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    return db_hl_walk(dbctx->dbh, (db_hl_walk_cb_t)fn, wctx);
}

int
back_end_dbm_iter_new(void **iter, void *ctx)
{
    int err;
    struct db_iter *ret;
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    err = db_hl_iter_new(&ret->iter, dbctx->dbh);
    if (err)
        goto err1;

    ret->dbctx = dbctx;

    ret->srch_key = do_malloc(dbctx->key_size);
    if (ret->srch_key == NULL)
        goto err2;
    ret->srch_status = -EINVAL;

    *iter = ret;
    return 0;

err2:
    db_hl_iter_free(ret->iter);
err1:
    free(ret);
    return err;
}

int
back_end_dbm_iter_free(void *iter)
{
    int err;
    struct db_iter *iterator = (struct db_iter *)iter;

    free(iterator->srch_key);

    err = db_hl_iter_free(iterator->iter);

    free(iter);

    return err;
}

int
back_end_dbm_iter_get(void *iter, void *retkey, void *retdata,
                      size_t *retdatasize)
{
    db_hl_iter_t dbiter;
    int res;
    size_t datalen;
    struct db_ctx *dbctx;
    struct db_iter *iterator = (struct db_iter *)iter;

    dbiter = iterator->iter;
    dbctx = iterator->dbctx;

    if (retdatasize == NULL)
        retdatasize = &datalen;

    if (iterator->srch_status == 0) {
        assert(dbctx->key_ctx->last_key_valid);

        res = db_hl_iter_search(dbiter, dbctx->key_ctx->last_key);
        assert(res != 0);
        if (res < 0)
            return res;

        if ((*(dbctx->key_cmp))(dbctx->key_ctx->last_key, iterator->srch_key,
                                NULL)
            < 0) {
            res = db_hl_iter_next(dbiter);
            if (res != 0)
                return res;
        }
    }

    return db_hl_iter_get(dbiter, retkey, retdata, retdatasize);
}

int
back_end_dbm_iter_next(void *iter)
{
    int err;
    struct db_iter *iterator = (struct db_iter *)iter;

    err = db_hl_iter_next(iterator->iter);

    iterator->srch_status = err ? err : 1;

    return err;
}

int
back_end_dbm_iter_search(void *iter, const void *key)
{
    struct db_ctx *dbctx;
    struct db_iter *iterator = (struct db_iter *)iter;

    dbctx = iterator->dbctx;

    dbctx->key_ctx->last_key_valid = 0;

    iterator->srch_status = db_hl_iter_search(iterator->iter, key);

    if (iterator->srch_status == 0)
        memcpy(iterator->srch_key, key, dbctx->key_size);

    return iterator->srch_status;
}

int
back_end_dbm_trans_new(void *ctx)
{
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    return db_hl_trans_new(dbctx->dbh);
}

int
back_end_dbm_trans_abort(void *ctx)
{
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    return db_hl_trans_abort(dbctx->dbh);
}

int
back_end_dbm_trans_commit(void *ctx)
{
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    return db_hl_trans_commit(dbctx->dbh);
}

int
back_end_dbm_sync(void *ctx)
{
    struct db_ctx *dbctx = (struct db_ctx *)ctx;

    return db_hl_sync(dbctx->dbh);
}

/* vi: set expandtab sw=4 ts=4: */
