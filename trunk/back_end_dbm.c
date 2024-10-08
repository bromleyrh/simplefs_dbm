/*
 * back_end_dbm.c
 */

#include "back_end.h"
#include "back_end_dbm.h"
#include "blkdev.h"
#include "common.h"
#include "util.h"

#include <dbm_high_level.h>

#include <files/acc_ctl.h>
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

#define ERR_PERIOD 1024

#define DB_HL_USEFSOPS 64
#define DB_HL_ALLOCHOOK 128

int back_end_err_test;
int back_end_io_err;

#define DO_ERR_INJECT(errnum, errret) \
    ERR_INJECT(back_end_err_test, ERR_PERIOD, errnum, errret, 0, func, file, \
               line, back_end_io_err)

int db_hl_get_trans_state(struct dbh *);

static void trans_cb(struct dbh *, int, int, int, void *);
static void sync_cb(struct dbh *, int, void *);

static int get_dir_relpath_components(struct db_args *, int *, const char **,
                                      char *, int);
static void release_dir(struct db_args *, int);

static int is_blkdev(int, const char *);

static int do_create(struct dbh **, int, const char *, mode_t, size_t,
                     back_end_key_cmp_t, void *, int, int, size_t *, size_t *,
                     uint64_t *, struct db_alloc_cb *);
static int do_open(struct dbh **, int, const char *, size_t, back_end_key_cmp_t,
                   void *, int, int, size_t *, size_t *, uint64_t *);

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
static int back_end_dbm_ctl(void *, int, void *);

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
    .sync           = &back_end_dbm_sync,
    .ctl            = &back_end_dbm_ctl
};

static int
__db_hl_create_blkdev(struct dbh **dbh, const char *pathname, mode_t mode,
                      size_t key_size, db_hl_key_cmp_t key_cmp, void *key_ctx,
                      int flags, int dfd, const struct fs_ops *fs_ops,
                      void *fs_args, void (*alloc_cb)(uint64_t, int, void *),
                      void *alloc_cb_ctx, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_create(dbh, pathname, mode, key_size, key_cmp, key_ctx, flags,
                        dfd, fs_ops, fs_args, alloc_cb, alloc_cb_ctx);
}

static int
__db_hl_create(struct dbh **dbh, const char *pathname, mode_t mode,
               size_t key_size, db_hl_key_cmp_t key_cmp, void *key_ctx,
               int flags, int dfd, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_create(dbh, pathname, mode, key_size, key_cmp, key_ctx, flags,
                        dfd);
}

static int
__db_hl_open_blkdev(struct dbh **dbh, const char *pathname, size_t key_size,
                    db_hl_key_cmp_t key_cmp, void *key_ctx, int flags, int dfd,
                    const struct fs_ops *fs_ops, void *fs_args,
                    SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_open(dbh, pathname, key_size, key_cmp, key_ctx, flags, dfd,
                      fs_ops, fs_args);
}

static int
__db_hl_open(struct dbh **dbh, const char *pathname, size_t key_size,
             db_hl_key_cmp_t key_cmp, void *key_ctx, int flags, int dfd,
             SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_open(dbh, pathname, key_size, key_cmp, key_ctx, flags, dfd);
}

static int
__db_hl_close(struct dbh *dbh, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_close(dbh);
}

static int
__db_hl_insert(struct dbh *dbh, const void *key, const void *data,
              size_t datasize, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_insert(dbh, key, data, datasize);
}

static int
__db_hl_replace(struct dbh *dbh, const void *key, const void *data,
                size_t datasize, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_replace(dbh, key, data, datasize);
}

static int
__db_hl_search(struct dbh *dbh, const void *key, void *retkey, void *retdata,
               size_t *retdatasize, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_search(dbh, key, retkey, retdata, retdatasize);
}

static int
__db_hl_delete(struct dbh *dbh, const void *key, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_delete(dbh, key);
}

static int
__db_hl_walk(struct dbh *dbh, db_hl_walk_cb_t fn, void *ctx, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_walk(dbh, fn, ctx);
}

static int
__db_hl_iter_new(db_hl_iter_t *iter, struct dbh *dbh, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_iter_new(iter, dbh);
}

static int
__db_hl_iter_free(db_hl_iter_t iter, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_iter_free(iter);
}

static int
__db_hl_iter_get(db_hl_iter_t iter, void *retkey, void *retdata,
                 size_t *retdatasize, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_iter_get(iter, retkey, retdata, retdatasize);
}

static int
__db_hl_iter_next(db_hl_iter_t iter, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_iter_next(iter);
}

static int
__db_hl_iter_search(db_hl_iter_t iter, const void *key, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_iter_search(iter, key);
}

static int
__db_hl_trans_new(struct dbh *dbh, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_trans_new(dbh);
}

static int
__db_hl_trans_abort(struct dbh *dbh, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_trans_abort(dbh);
}

static int
__db_hl_trans_commit(struct dbh *dbh, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_trans_commit(dbh);
}

static int
__db_hl_sync(struct dbh *dbh, SOURCE_LINE_PARAMS)
{
    DO_ERR_INJECT(0, -EIO);

    return db_hl_sync(dbh);
}

#define _db_hl_create_blkdev(dbh, pathname, mode, key_size, key_cmp, key_ctx, \
                             flags, dfd, fs_ops, fs_args, alloc_cb, \
                             alloc_cb_ctx) \
    __db_hl_create_blkdev(dbh, pathname, mode, key_size, key_cmp, key_ctx, \
                          flags, dfd, fs_ops, fs_args, alloc_cb, alloc_cb_ctx, \
                          SOURCE_LINE)
#define db_hl_create_blkdev(dbh, pathname, mode, key_size, key_cmp, key_ctx, \
                            flags, dfd, fs_ops, fs_args, alloc_cb, \
                            alloc_cb_ctx) \
    _db_hl_create_blkdev(dbh, pathname, mode, key_size, key_cmp, key_ctx, \
                         (flags) | DB_HL_RELPATH | DB_HL_USEFSOPS \
                         | DB_HL_ALLOCHOOK, \
                         dfd, fs_ops, fs_args, alloc_cb, alloc_cb_ctx)
#define _db_hl_create(dbh, pathname, mode, key_size, key_cmp, key_ctx, flags, \
                      dfd) \
    __db_hl_create(dbh, pathname, mode, key_size, key_cmp, key_ctx, flags, \
                   dfd, SOURCE_LINE)
#define db_hl_create(dbh, pathname, mode, key_size, key_cmp, key_ctx, flags, \
                     dfd) \
    _db_hl_create(dbh, pathname, mode, key_size, key_cmp, key_ctx, \
                  (flags) | DB_HL_RELPATH, dfd)

#define _db_hl_open_blkdev(dbh, pathname, key_size, key_cmp, key_ctx, flags, \
                           dfd, fs_ops, fs_args) \
    __db_hl_open_blkdev(dbh, pathname, key_size, key_cmp, key_ctx, flags, dfd, \
                        fs_ops, fs_args, SOURCE_LINE)
#define db_hl_open_blkdev(dbh, pathname, key_size, key_cmp, key_ctx, flags, \
                          dfd, fs_ops, fs_args) \
    _db_hl_open_blkdev(dbh, pathname, key_size, key_cmp, key_ctx, \
                       (flags) | DB_HL_RELPATH | DB_HL_USEFSOPS, dfd, fs_ops, \
                       fs_args)
#define _db_hl_open(dbh, pathname, key_size, key_cmp, key_ctx, flags, dfd) \
    __db_hl_open(dbh, pathname, key_size, key_cmp, key_ctx, flags, dfd, \
                 SOURCE_LINE)
#define db_hl_open(dbh, pathname, key_size, key_cmp, key_ctx, flags, dfd) \
    _db_hl_open(dbh, pathname, key_size, key_cmp, key_ctx, \
                (flags) | DB_HL_RELPATH, dfd)

#define db_hl_close(dbh) \
    __db_hl_close(dbh, SOURCE_LINE)

#define db_hl_insert(dbh, key, data, datasize) \
    __db_hl_insert(dbh, key, data, datasize, SOURCE_LINE)
#define db_hl_replace(dbh, key, data, datasize) \
    __db_hl_replace(dbh, key, data, datasize, SOURCE_LINE)
#define db_hl_search(dbh, key, retkey, retdata, retdatasize) \
    __db_hl_search(dbh, key, retkey, retdata, retdatasize, SOURCE_LINE)
#define db_hl_delete(dbh, key) \
    __db_hl_delete(dbh, key, SOURCE_LINE)

#define db_hl_walk(dbh, fn, ctx) \
    __db_hl_walk(dbh, fn, ctx, SOURCE_LINE)

#define db_hl_iter_new(iter, dbh) \
    __db_hl_iter_new(iter, dbh, SOURCE_LINE)
#define db_hl_iter_free(iter) \
    __db_hl_iter_free(iter, SOURCE_LINE)
#define db_hl_iter_get(iter, retkey, retdata, retdatasize) \
    __db_hl_iter_get(iter, retkey, retdata, retdatasize, SOURCE_LINE)
#define db_hl_iter_next(iter) \
    __db_hl_iter_next(iter, SOURCE_LINE)
#define db_hl_iter_search(iter, key) \
    __db_hl_iter_search(iter, key, SOURCE_LINE)

#define db_hl_trans_new(dbh) \
    __db_hl_trans_new(dbh, SOURCE_LINE)
#define db_hl_trans_abort(dbh) \
    __db_hl_trans_abort(dbh, SOURCE_LINE)
#define db_hl_trans_commit(dbh) \
    __db_hl_trans_commit(dbh, SOURCE_LINE)

#define db_hl_sync(dbh) \
    __db_hl_sync(dbh, SOURCE_LINE)

static void
trans_cb(struct dbh *dbh, int trans_type, int act, int status, void *ctx)
{
    struct db_ctx *dbctx = ctx;

    (void)dbh;

    (*dbctx->trans_cb)(trans_type, act, status, dbctx->trans_ctx);
}

static void
sync_cb(struct dbh *dbh, int status, void *ctx)
{
    struct db_ctx *dbctx = ctx;

    (void)dbh;

    (*dbctx->sync_cb)(status, dbctx->sync_ctx);
}

static int
get_dir_relpath_components(struct db_args *dbargs, int *dfd,
                           const char **relpathname, char *buf, int create)
{
    const char *pathname = dbargs->db_pathname;
    int fd;

    if (dbargs->wd >= 0) {
        *dfd = dbargs->wd;
        *relpathname = pathname;
        return 0;
    }

    if (dirname_safe(pathname, buf, PATH_MAX) == NULL)
        return -ENAMETOOLONG;

    fd = open(buf, O_CLOEXEC | O_DIRECTORY
                   | (create ? O_RDONLY : OPEN_MODE_EXEC));
    if (fd == -1)
        return MINUS_ERRNO;

    *dfd = fd;
    *relpathname = basename_safe(pathname);
    return 0;
}

static void
release_dir(struct db_args *dbargs, int dfd)
{
    if (dfd != dbargs->wd)
        close(dfd);
}

static int
is_blkdev(int dfd, const char *pathname)
{
    struct stat s;

    /* Time-of-check to time-of-use race conditions are avoided as follows. If
     * this function returns a block device type, this module relies on the
     * FS_BLKDEV_OPS implementation to return an error if the pathname no longer
     * resolves to a block device. If this function returns a non-block-device
     * type, this module relies on the DBM implementation to return an error if
     * the pathname no longer resolves to a regular file. */
    if (fstatat(dfd, pathname, &s, 0) == -1)
        return errno == ENOENT ? 0 : MINUS_ERRNO;

    return (s.st_mode & S_IFMT) == S_IFBLK;
}

static int
do_create(struct dbh **dbh, int dfd, const char *relpath, mode_t mode,
          size_t key_size, back_end_key_cmp_t key_cmp, void *key_ctx, int flags,
          int blkdev, size_t *hdr_len, size_t *jlen, uint64_t *blkdev_size,
          struct db_alloc_cb *alloc_cb)
{
    db_hl_key_cmp_t keycmp = key_cmp;
    int err;

    if (blkdev) {
        struct blkdev_args args;

        err = db_hl_create_blkdev(dbh, relpath, mode, key_size, keycmp, key_ctx,
                                  flags, dfd, FS_BLKDEV_OPS, &args,
                                  alloc_cb->alloc_cb, alloc_cb->alloc_cb_ctx);
        if (!err) {
            *hdr_len = args.hdrlen;
            *jlen = args.jlen;
            *blkdev_size = args.blkdevsz;
        }
        return err;
    }

    return db_hl_create(dbh, relpath, mode, key_size, keycmp, key_ctx,
                        flags | DB_HL_RELPATH, dfd);
}

static int
do_open(struct dbh **dbh, int dfd, const char *relpath, size_t key_size,
        back_end_key_cmp_t key_cmp, void *key_ctx, int flags,
        int blkdev, size_t *hdr_len, size_t *jlen, uint64_t *blkdev_size)
{
    db_hl_key_cmp_t keycmp = key_cmp;
    int err;

    if (blkdev) {
        struct blkdev_args args;

        err = db_hl_open_blkdev(dbh, relpath, key_size, keycmp, key_ctx, flags,
                                dfd, FS_BLKDEV_OPS, &args);
        if (!err) {
            *hdr_len = args.hdrlen;
            *jlen = args.jlen;
            *blkdev_size = args.blkdevsz;
        }
        return err;
    }

    return db_hl_open(dbh, relpath, key_size, keycmp, key_ctx,
                      flags | DB_HL_RELPATH, dfd);
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
    char buf[PATH_MAX];
    const char *relpath;
    int blkdev;
    int dfd;
    int err;
    int flags;
    size_t hdrlen, jlen;
    struct db_args *dbargs = args;
    struct db_ctx *ret;
    uint64_t blkdevsz;

    err = get_dir_relpath_components(dbargs, &dfd, &relpath, buf, 1);
    if (err)
        return err;

    blkdev = is_blkdev(dfd, relpath);
    if (blkdev < 0) {
        err = blkdev;
        goto err1;
    }

    if (oemalloc(&ret) == NULL) {
        err = MINUS_ERRNO;
        goto err1;
    }
    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    if (oemalloc(&ret->key_ctx) == NULL) {
        err = MINUS_ERRNO;
        goto err2;
    }

    ret->key_ctx->last_key = do_malloc(key_size);
    if (ret->key_ctx->last_key == NULL) {
        err = MINUS_ERRNO;
        goto err3;
    }
    ret->key_ctx->last_key_valid = 0;

    if (dbargs->lkw)
        flags = DB_HL_LKW;
    else
        flags = 0;

    hdrlen = jlen = 0;
    blkdevsz = 0;
    err = do_create(&ret->dbh, dfd, relpath, dbargs->db_mode, key_size, key_cmp,
                    ret->key_ctx, flags, blkdev, &hdrlen, &jlen, &blkdevsz,
                    &dbargs->alloc_cb);
    if (err)
        goto err4;

    if (dbargs->trans_cb) {
        err = db_hl_ctl(ret->dbh, DB_HL_OP_SET_CB, &trans_cb, ret, NULL);
        if (err)
            goto err5;
        ret->trans_cb = dbargs->trans_cb;
        ret->trans_ctx = dbargs->trans_ctx;
    }
    if (dbargs->sync_cb) {
        err = db_hl_ctl(ret->dbh, DB_HL_OP_SYNC_SET_CB, &sync_cb, ret, NULL);
        if (err)
            goto err5;
        ret->sync_cb = dbargs->sync_cb;
        ret->sync_ctx = dbargs->sync_ctx;
    }

    release_dir(dbargs, dfd);

    dbargs->blkdev = blkdev;
    dbargs->hdrlen = hdrlen;
    dbargs->jlen = jlen;
    dbargs->blkdevsz = blkdevsz;

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
    release_dir(dbargs, dfd);
    return err;
}

int
back_end_dbm_open(void **ctx, size_t key_size, back_end_key_cmp_t key_cmp,
                  void *args)
{
    char buf[PATH_MAX];
    const char *relpath;
    int blkdev;
    int dfd;
    int err;
    int flags;
    size_t hdrlen, jlen;
    struct db_args *dbargs = args;
    struct db_ctx *ret;
    uint64_t blkdevsz;

    err = get_dir_relpath_components(dbargs, &dfd, &relpath, buf, 0);
    if (err)
        return err;

    blkdev = is_blkdev(dfd, relpath);
    if (blkdev < 0) {
        err = blkdev;
        goto err1;
    }

    if (oemalloc(&ret) == NULL) {
        err = MINUS_ERRNO;
        goto err1;
    }
    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    if (oemalloc(&ret->key_ctx) == NULL) {
        err = MINUS_ERRNO;
        goto err2;
    }

    ret->key_ctx->last_key = do_malloc(key_size);
    if (ret->key_ctx->last_key == NULL) {
        err = MINUS_ERRNO;
        goto err3;
    }
    ret->key_ctx->last_key_valid = 0;

    if (dbargs->lkw)
        flags = DB_HL_LKW;
    else
        flags = 0;

    /* test for journal replay by attempting read-only open */
    hdrlen = jlen = 0;
    blkdevsz = 0;
    err = do_open(&ret->dbh, dfd, relpath, key_size, key_cmp, ret->key_ctx,
                  flags | DB_HL_RDONLY, blkdev, &hdrlen, &jlen, &blkdevsz);
    if (!dbargs->ro) {
        if (err) {
            if (err != -EROFS)
                goto err4;
            infomsg("Replaying file system journal\n");
        } else {
            err = db_hl_close(ret->dbh);
            if (err)
                goto err4;
        }

        err = do_open(&ret->dbh, dfd, relpath, key_size, key_cmp, ret->key_ctx,
                      flags | DB_HL_RELPATH, blkdev, &hdrlen, &jlen, &blkdevsz);
    }
    if (err)
        goto err4;

    if (dbargs->trans_cb) {
        err = db_hl_ctl(ret->dbh, DB_HL_OP_SET_CB, &trans_cb, ret, NULL);
        if (err)
            goto err4;
        ret->trans_cb = dbargs->trans_cb;
        ret->trans_ctx = dbargs->trans_ctx;
    }
    if (dbargs->sync_cb) {
        err = db_hl_ctl(ret->dbh, DB_HL_OP_SYNC_SET_CB, &sync_cb, ret, NULL);
        if (err)
            goto err5;
        ret->sync_cb = dbargs->sync_cb;
        ret->sync_ctx = dbargs->sync_ctx;
    }

    release_dir(dbargs, dfd);

    dbargs->blkdev = blkdev;
    dbargs->hdrlen = hdrlen;
    dbargs->jlen = jlen;
    dbargs->blkdevsz = blkdevsz;

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
    release_dir(dbargs, dfd);
    return err;
}

int
back_end_dbm_close(void *ctx)
{
    int err;
    struct db_ctx *dbctx = ctx;

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
    struct db_ctx *dbctx = ctx;

    return db_hl_insert(dbctx->dbh, key, data, datasize);
}

int
back_end_dbm_replace(void *ctx, const void *key, const void *data,
                     size_t datasize)
{
    struct db_ctx *dbctx = ctx;

    return db_hl_replace(dbctx->dbh, key, data, datasize);
}

int
back_end_dbm_look_up(void *ctx, const void *key, void *retkey, void *retdata,
                     size_t *retdatasize, int look_up_nearest)
{
    int res;
    size_t datalen;
    struct db_ctx *dbctx = ctx;

    if (retdatasize == NULL)
        retdatasize = &datalen;

    dbctx->key_ctx->last_key_valid = 0;

    res = db_hl_search(dbctx->dbh, key, retkey, retdata, retdatasize);

    if (look_up_nearest && res == 0 && dbctx->key_ctx->last_key_valid) {
        int cmp;

        cmp = (*dbctx->key_cmp)(dbctx->key_ctx->last_key, key, NULL);
        if (cmp > 0) {
            res = db_hl_search(dbctx->dbh, dbctx->key_ctx->last_key, retkey,
                               retdata, retdatasize);
            assert(res != 0);
            return res == 1 ? 2 : res;
        }
        res = get_next_elem(retkey, retdata, retdatasize,
                            dbctx->key_ctx->last_key, dbctx);
        if (res != 0)
            return res == -EADDRNOTAVAIL ? 0: res;
        return 2;
    }

    return res;
}

int
back_end_dbm_delete(void *ctx, const void *key)
{
    struct db_ctx *dbctx = ctx;

    return db_hl_delete(dbctx->dbh, key);
}

int
back_end_dbm_walk(void *ctx, back_end_walk_cb_t fn, void *wctx)
{
    struct db_ctx *dbctx = ctx;

    return db_hl_walk(dbctx->dbh, (db_hl_walk_cb_t)fn, wctx);
}

int
back_end_dbm_iter_new(void **iter, void *ctx)
{
    int err;
    struct db_iter *ret;
    struct db_ctx *dbctx = ctx;

    if (oemalloc(&ret) == NULL)
        return MINUS_ERRNO;

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
    struct db_iter *iterator = iter;

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
    struct db_iter *iterator = iter;

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

        if ((*dbctx->key_cmp)(dbctx->key_ctx->last_key, iterator->srch_key,
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
    struct db_iter *iterator = iter;

    err = db_hl_iter_next(iterator->iter);

    iterator->srch_status = err ? err : 1;

    return err;
}

int
back_end_dbm_iter_search(void *iter, const void *key)
{
    struct db_ctx *dbctx;
    struct db_iter *iterator = iter;

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
    struct db_ctx *dbctx = ctx;

    return db_hl_trans_new(dbctx->dbh);
}

int
back_end_dbm_trans_abort(void *ctx)
{
    struct db_ctx *dbctx = ctx;

    return db_hl_trans_abort(dbctx->dbh);
}

int
back_end_dbm_trans_commit(void *ctx)
{
    struct db_ctx *dbctx = ctx;

    return db_hl_trans_commit(dbctx->dbh);
}

int
back_end_dbm_sync(void *ctx)
{
    struct db_ctx *dbctx = ctx;

    return db_hl_sync(dbctx->dbh);
}

int
back_end_dbm_ctl(void *ctx, int op, void *args)
{
    int err;
    struct db_alloc_cb *alloc_cb;
    struct db_ctx *dbctx = ctx;

    switch (op) {
    case BACK_END_DBM_OP_GET_HDR_LEN:
        err = db_hl_ctl(dbctx->dbh, DB_HL_OP_GET_HDR_LEN, args);
        break;
    case BACK_END_DBM_OP_FOREACH_ALLOC:
    case BACK_END_DBM_OP_SET_ALLOC_HOOK:
        alloc_cb = args;
        err = db_hl_ctl(dbctx->dbh,
                        op == BACK_END_DBM_OP_FOREACH_ALLOC
                        ? DB_HL_OP_FOREACH_ALLOC : DB_HL_OP_SET_ALLOC_HOOK,
                        alloc_cb->alloc_cb, alloc_cb->alloc_cb_ctx);
        break;
    default:
        err = -EINVAL;
    }

    return err;
}

void
back_end_dbm_disable_iter_commit(void *ctx)
{
    struct db_ctx *dbctx = ctx;

    db_hl_ctl(dbctx->dbh, DB_HL_OP_SET_ITER_COMMIT, 0);
}

int
back_end_dbm_get_trans_state(void *ctx)
{
    struct db_ctx *dbctx = ctx;

    return db_hl_ctl(dbctx->dbh, DB_HL_OP_GET_TRANS_STATE);
}

/* vi: set expandtab sw=4 ts=4: */
