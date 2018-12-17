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

struct db_key {
    fuse_ino_t  dir_ino;
    const char  name[NAME_MAX+1];
};

struct db_data {
    fuse_ino_t ino;
};

static int uint64_cmp(uint64_t, uint64_t);

static int db_key_cmp(const void *, const void *, void *);

static int
uint64_cmp(uint64_t n1, uint64_t n2)
{
    return (n1 > n2) - (n1 < n2);
}

static int
db_key_cmp(const void *k1, const void *k2, void *key_ctx)
{
    int cmp;
    struct db_key *key1 = (struct db_key *)k1;
    struct db_key *key2 = (struct db_key *)k2;

    (void)key_ctx;

    cmp = uint64_cmp((uint64_t)(key1->dir_ino), (uint64_t)(key2->dir_ino));
    if (cmp != 0)
        return cmp;

    return strcmp(key1->name, key2->name);
}

int
back_end_create(struct back_end **be, int root_id, void *args)
{
    int err;
    struct back_end *ret;
    struct db_args *dbargs = (struct db_args *)args;
    struct db_ctx *dbctx;

    (void)root_id;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    dbctx = do_malloc(sizeof(*dbctx));
    if (dbctx == NULL) {
        err = -errno;
        goto err1;
    }
    ret->ctx = dbctx;

    err = db_create(&dbctx->db, dbargs->db_pathname, dbargs->db_mode,
                    sizeof(struct db_key), &db_key_cmp, dbctx, 0);
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
back_end_open(struct back_end **be, void *args)
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

    err = db_open(&dbctx->db, dbargs->db_pathname, sizeof(struct db_key),
                  &db_key_cmp, dbctx, 0);
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

/* vi: set expandtab sw=4 ts=4: */
