/*
 * fuse_cache.c
 */

#include "back_end.h"
#include "fuse_cache.h"
#include "util.h"

#include <avl_tree.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

enum op_type {
    INSERT = 1,
    REPLACE,
    DELETE
};

struct op {
    enum op_type    op;
    const void      *key;
    const void      *data;
    size_t          datasize;
};

struct fuse_cache {
    struct avl_tree             *cache;
    void                        *ctx;
    const struct back_end_ops   *ops;
    struct op                   *op_list;
    size_t                      ops_len;
    size_t                      ops_size;
};

struct fuse_cache_iter {
    void                *iter;
    struct fuse_cache   *cache;
};

static int fuse_cache_create(void **, size_t, back_end_key_cmp_t, void *);
static int fuse_cache_open(void **, size_t, back_end_key_cmp_t, void *);
static int fuse_cache_close(void *);
static int fuse_cache_insert(void *, const void *, const void *, size_t);
static int fuse_cache_replace(void *, const void *, const void *, size_t);
static int fuse_cache_look_up(void *, const void *, void *, void *, size_t *,
                              int);
static int fuse_cache_delete(void *, const void *);
static int fuse_cache_walk(void *, back_end_walk_cb_t, void *);
static int fuse_cache_iter_new(void **, void *);
static int fuse_cache_iter_free(void *);
static int fuse_cache_iter_get(void *, void *, void *, size_t *);
static int fuse_cache_iter_next(void *);
static int fuse_cache_iter_search(void *, const void *);
static int fuse_cache_trans_new(void *);
static int fuse_cache_trans_abort(void *);
static int fuse_cache_trans_commit(void *);
static int fuse_cache_sync(void *);

const struct back_end_ops back_end_fuse_cache_ops = {
    .create         = &fuse_cache_create,
    .open           = &fuse_cache_open,
    .close          = &fuse_cache_close,
    .insert         = &fuse_cache_insert,
    .replace        = &fuse_cache_replace,
    .look_up        = &fuse_cache_look_up,
    .delete         = &fuse_cache_delete,
    .walk           = &fuse_cache_walk,
    .iter_new       = &fuse_cache_iter_new,
    .iter_free      = &fuse_cache_iter_free,
    .iter_get       = &fuse_cache_iter_get,
    .iter_next      = &fuse_cache_iter_next,
    .iter_search    = &fuse_cache_iter_search,
    .trans_new      = &fuse_cache_trans_new,
    .trans_abort    = &fuse_cache_trans_abort,
    .trans_commit   = &fuse_cache_trans_commit,
    .sync           = &fuse_cache_sync
};

static int
fuse_cache_create(void **ctx, size_t key_size, back_end_key_cmp_t key_cmp,
                  void *args)
{
    int err;
    struct fuse_cache *ret;
    struct fuse_cache_args *cache_args = (struct fuse_cache_args *)args;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    err = avl_tree_new(&ret->cache, key_size, key_cmp, 0, NULL, NULL, NULL);
    if (err)
        goto err1;

    err = (*(cache_args->ops->create))(&ret->ctx, key_size, key_cmp,
                                       cache_args->args);
    if (err)
        goto err2;

    ret->ops = cache_args->ops;

    ret->op_list = NULL;
    ret->ops_len = ret->ops_size = 0;

    *ctx = ret;
    return 0;

err2:
    avl_tree_free(ret->cache);
err1:
    free(ret);
    return err;
}

static int
fuse_cache_open(void **ctx, size_t key_size, back_end_key_cmp_t key_cmp,
                void *args)
{
    int err;
    struct fuse_cache *ret;
    struct fuse_cache_args *cache_args = (struct fuse_cache_args *)args;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    err = avl_tree_new(&ret->cache, key_size, key_cmp, 0, NULL, NULL, NULL);
    if (err)
        goto err1;

    err = (*(cache_args->ops->open))(&ret->ctx, key_size, key_cmp,
                                     cache_args->args);
    if (err)
        goto err2;

    ret->ops = cache_args->ops;

    ret->op_list = NULL;
    ret->ops_len = ret->ops_size = 0;

    *ctx = ret;
    return 0;

err2:
    avl_tree_free(ret->cache);
err1:
    free(ret);
    return err;
}

static int
fuse_cache_close(void *ctx)
{
    int err, tmp;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    err = (*(cache->ops->close))(cache->ctx);

    tmp = avl_tree_free(cache->cache);
    if (tmp != 0)
        err = tmp;

    free(cache);

    return err;
}

static int
fuse_cache_insert(void *ctx, const void *key, const void *data, size_t datasize)
{
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    return (*(cache->ops->insert))(cache->ctx, key, data, datasize);
}

static int
fuse_cache_replace(void *ctx, const void *key, const void *data,
                   size_t datasize)
{
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    return (*(cache->ops->replace))(cache->ctx, key, data, datasize);
}

static int
fuse_cache_look_up(void *ctx, const void *key, void *retkey, void *retdata,
                   size_t *retdatasize, int look_up_nearest)
{
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    return (*(cache->ops->look_up))(cache->ctx, key, retkey, retdata,
                                    retdatasize, look_up_nearest);
}

static int
fuse_cache_delete(void *ctx, const void *key)
{
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    return (*(cache->ops->delete))(cache->ctx, key);
}

static int
fuse_cache_walk(void *ctx, back_end_walk_cb_t fn, void *wctx)
{
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    return (*(cache->ops->walk))(cache->ctx, fn, wctx);
}

static int
fuse_cache_iter_new(void **iter, void *ctx)
{
    int err;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;
    struct fuse_cache_iter *ret;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    err = (*(cache->ops->iter_new))(&ret->iter, cache->ctx);
    if (err) {
        free(ret);
        return err;
    }

    *iter = ret;
    return 0;
}

static int
fuse_cache_iter_free(void *iter)
{
    int err;
    struct fuse_cache_iter *iterator = (struct fuse_cache_iter *)iter;

    err = (*(iterator->cache->ops->iter_free))(iterator->iter);

    free(iterator);

    return err;
}

static int
fuse_cache_iter_get(void *iter, void *retkey, void *retdata,
                    size_t *retdatasize)
{
    struct fuse_cache_iter *iterator = (struct fuse_cache_iter *)iter;

    return (*(iterator->cache->ops->iter_get))(iterator->iter, retkey, retdata,
                                               retdatasize);
}

static int
fuse_cache_iter_next(void *iter)
{
    struct fuse_cache_iter *iterator = (struct fuse_cache_iter *)iter;

    return (*(iterator->cache->ops->iter_next))(iterator->iter);
}

static int
fuse_cache_iter_search(void *iter, const void *key)
{
    struct fuse_cache_iter *iterator = (struct fuse_cache_iter *)iter;

    return (*(iterator->cache->ops->iter_search))(iterator->iter, key);
}

static int
fuse_cache_trans_new(void *ctx)
{
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    return (*(cache->ops->trans_new))(cache->ctx);
}

static int
fuse_cache_trans_abort(void *ctx)
{
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    return (*(cache->ops->trans_abort))(cache->ctx);
}

static int
fuse_cache_trans_commit(void *ctx)
{
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    return (*(cache->ops->trans_commit))(cache->ctx);
}

static int
fuse_cache_sync(void *ctx)
{
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    return (*(cache->ops->sync))(cache->ctx);
}

/* vi: set expandtab sw=4 ts=4: */
