/*
 * back_end.c
 */

#include "back_end.h"
#include "util.h"

#include <dbm.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fuse.h>
#include <fuse_lowlevel.h>

#include <limits.h>

struct back_end {
    void *ctx;
    void *args;
};

struct db_ctx {
    struct db *db;
};

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
    ret->ctx = dbctx;

    err = db_create(&dbctx->db, dbargs->db_pathname, dbargs->db_mode, key_size,
                    key_cmp, dbctx, 0);
    if (err)
        goto err2;

    *be = ret;
    return 0;

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
    ret->ctx = dbctx;

    err = db_open(&dbctx->db, dbargs->db_pathname, key_size, key_cmp, dbctx, 0);
    if (err)
        goto err2;

    *be = ret;
    return 0;

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
    size_t datalen;
    struct db_ctx *dbctx = (struct db_ctx *)(be->ctx);

    return db_search(dbctx->db, key, NULL, retdata, &datalen);
}

/* vi: set expandtab sw=4 ts=4: */
