/*
 * back_end.c
 */

#include "back_end.h"
#include "util.h"

#include <dbm.h>

#include <fuse.h>
#include <fuse_lowlevel.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct back_end {
    void *ctx;
    void *args;
};

struct back_end_iter {
    void            *ctx;
    void            *srch_key;
    int             srch_status;
    struct back_end *be;
};

struct db_ctx {
    struct db               *db;
    size_t                  key_size;
    back_end_key_cmp_t      key_cmp;
    struct back_end_key_ctx *key_ctx;
};

static int get_next_val(void *, const void *, struct db_ctx *);

static int
get_next_val(void *next_val, const void *key, struct db_ctx *dbctx)
{
    db_iter_t iter;
    int res;
    size_t datalen;

    res = db_iter_new(&iter, dbctx->db);
    if (res != 0)
        return res;

    res = db_iter_search(iter, key);
    if (res != 0)
        goto end;

    res = db_iter_next(iter);
    if (res != 0)
        goto end;

    res = db_iter_get(iter, NULL, next_val, &datalen);

end:
    db_iter_free(iter);
    return res;
}

int
back_end_create(struct back_end **be, size_t key_size,
                back_end_key_cmp_t key_cmp, void *args)
{
    int err;
    struct back_end *ret;
    struct db_args *dbargs = (struct db_args *)args;
    struct db_ctx *dbctx;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    dbctx = do_malloc(sizeof(*dbctx));
    if (dbctx == NULL) {
        err = -errno;
        goto err1;
    }
    dbctx->key_size = key_size;
    dbctx->key_cmp = key_cmp;
    ret->ctx = dbctx;

    dbctx->key_ctx = do_malloc(sizeof(*(dbctx->key_ctx)));
    if (dbctx->key_ctx == NULL) {
        err = -errno;
        goto err2;
    }

    dbctx->key_ctx->last_key = do_malloc(key_size);
    if (dbctx->key_ctx->last_key == NULL) {
        err = -errno;
        goto err3;
    }
    dbctx->key_ctx->last_key_valid = 0;

    err = db_create(&dbctx->db, dbargs->db_pathname, dbargs->db_mode, key_size,
                    key_cmp, dbctx->lastkey, 0);
    if (err)
        goto err4;

    *be = ret;
    return 0;

err4:
    free(dbctx->key_ctx->last_key);
err3:
    free(dbctx->key_ctx);
err2:
    free(dbctx);
err1:
    free(ret);
    return err;
}

int
back_end_open(struct back_end **be, size_t key_size, back_end_key_cmp_t key_cmp,
              void *args)
{
    int err;
    struct back_end *ret;
    struct db_args *dbargs = (struct db_args *)args;
    struct db_ctx *dbctx;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    dbctx = do_malloc(sizeof(*dbctx));
    if (dbctx == NULL) {
        err = -errno;
        goto err1;
    }
    dbctx->key_size = key_size;
    dbctx->key_cmp = key_cmp;
    ret->ctx = dbctx;

    dbctx->key_ctx = do_malloc(sizeof(*(dbctx->key_ctx)));
    if (dbctx->key_ctx == NULL) {
        err = -errno;
        goto err2;
    }

    dbctx->key_ctx->last_key = do_malloc(key_size);
    if (dbctx->key_ctx->last_key == NULL) {
        err = -errno;
        goto err3;
    }
    dbctx->key_ctx->last_key_valid = 0;

    err = db_open(&dbctx->db, dbargs->db_pathname, key_size, key_cmp,
                  dbctx->lastkey, 0);
    if (err)
        goto err4;

    *be = ret;
    return 0;

err4:
    free(dbctx->key_ctx->last_key);
err3:
    free(dbctx->key_ctx);
err2:
    free(dbctx);
err1:
    free(ret);
    return err;
}

int
back_end_close(struct back_end *be)
{
    int err;
    struct db_ctx *dbctx = (struct db_ctx *)(be->ctx);

    err = db_close(dbctx->db);

    free(dbctx->key_ctx->last_key);

    free(dbctx->key_ctx);

    free(dbctx);

    free(be);

    return err;
}

int
back_end_insert(struct back_end *be, const void *key, const void *data,
                size_t datasize)
{
    struct db_ctx *dbctx = (struct db_ctx *)(be->ctx);

    return db_insert(dbctx->db, key, data, datasize);
}

int
back_end_look_up(struct back_end *be, const void *key, void *retdata)
{
    int res;
    size_t datalen;
    struct db_ctx *dbctx = (struct db_ctx *)(be->ctx);

    dbctx->key_ctx->last_key_valid = 0;

    res = db_search(dbctx->db, key, NULL, retdata, &datalen);

    if ((res == 0) && dbctx->key_ctx->last_key_valid) {
        int cmp;

        cmp = (*(dbctx->key_cmp))(dbctx->key_ctx->last_key, key, NULL);
        if (cmp > 0) {
            return db_search(dbctx->db, dbctx->key_ctx->last_key, NULL, retdata,
                             &datalen);
        }
        return get_next_val(retdata, dbctx->key_ctx->last_key, dbctx);
    }

    return res;
}

int
back_end_iter_new(struct back_end_iter **iter, struct back_end *be)
{
    int err;
    struct back_end_iter *ret;
    struct db_ctx *dbctx = (struct db_ctx *)(be->ctx);

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    err = db_iter_new(&ret->ctx, dbctx->db);
    if (err)
        goto err1;

    ret->be = be;

    ret->srch_key = do_malloc(dbctx->key_size);
    if (ret->srch_key == NULL)
        goto err2;

    return 0;

err2:
    db_iter_free((db_iter_t)(ret->ctx));
err1:
    free(ret);
    return err;
}

int
back_end_iter_free(struct back_end_iter *iter)
{
    int err;

    free(iter->srch_key);

    err = db_iter_free((db_iter_t)(iter->ctx));

    free(iter);

    return err;
}

int
back_end_iter_get(struct back_end_iter *iter, void *retdata)
{
    int err;
    size_t datalen;
    struct db_ctx *dbctx = (struct db_ctx *)(iter->be->ctx);

    if (iter->srch_status == 0) {
        int cmp;

        assert(dbctx->key_ctx->last_key_valid);

        cmp = (*(dbctx->key_cmp))(dbctx->key_ctx->last_key, iter->srch_key,
                                  NULL);
        if (cmp > 0) {
            return db_search(dbctx->db, dbctx->key_ctx->last_key, NULL, retdata,
                             &datalen);
        }
        return get_next_val(retdata, dbctx->key_ctx->last_key, dbctx);
    }

    return db_iter_get((db_iter_t)(iter->ctx), NULL, retdata, &datalen);
}

int
back_end_iter_next(struct back_end_iter *iter)
{
    return db_iter_next((db_iter_t)(iter->ctx));
}

int
back_end_iter_search(struct back_end_iter *iter, const void *key)
{
    struct db_ctx *dbctx = (struct db_ctx *)(iter->be->ctx);

    dbctx->key_ctx->last_key_valid = 0;

    iter->srch_status = db_iter_search((db_iter_t)(iter->ctx), key);

    if (iter->srch_status == 0)
        memcpy(dbctx->srch_key, key, dbctx->key_size);

    return iter->srch_status;
}

int
back_end_trans_new(struct back_end *be)
{
    struct db_ctx *dbctx = (struct db_ctx *)(be->ctx);

    return db_trans_new(dbctx->db);
}

int
back_end_trans_abort(struct back_end *be)
{
    struct db_ctx *dbctx = (struct db_ctx *)(be->ctx);

    return db_trans_abort(dbctx->db);
}

int
back_end_trans_commit(struct back_end *be)
{
    struct db_ctx *dbctx = (struct db_ctx *)(be->ctx);

    return db_trans_commit(dbctx->db);
}

/* vi: set expandtab sw=4 ts=4: */
