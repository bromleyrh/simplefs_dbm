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
#include <string.h>

struct cache_obj {
    const void  *key;
    const void  *data;
    size_t      datasize;
};

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
    size_t                      key_size;
    back_end_key_cmp_t          key_cmp;
    struct avl_tree             *trans;
    int                         trans_valid;
};

struct fuse_cache_iter {
    void                *iter;
    struct fuse_cache   *cache;
};

static int cache_obj_cmp(const void *, const void *, void *);
static int op_cmp(const void *, const void *, void *);

static int init_cache_obj(struct cache_obj *, const void *, const void *,
                          size_t, struct fuse_cache *);
static void destroy_cache_obj(struct cache_obj *);

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
cache_obj_cmp(const void *k1, const void *k2, void *ctx)
{
    struct cache_obj *o1 = *(struct cache_obj **)k1;
    struct cache_obj *o2 = *(struct cache_obj **)k2;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    return (*(cache->key_cmp))(o1->key, o2->key, NULL);
}

static int
op_cmp(const void *k1, const void *k2, void *ctx)
{
    int cmp;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;
    struct op *op1 = (struct op *)k1;
    struct op *op2 = (struct op *)k2;

    cmp = (op1->op > op2->op) - (op1->op < op2->op);
    if (cmp != 0)
        return cmp;

    return (*(cache->key_cmp))(op1->key, op2->key, NULL);
}

static int
init_cache_obj(struct cache_obj *o, const void *key, const void *data,
               size_t datasize, struct fuse_cache *cache)
{
    int err;
    void *k, *d;

    k = do_malloc(cache->key_size);
    if (k == NULL)
        return -errno;

    d = do_malloc(datasize);
    if (d == NULL) {
        err = -errno;
        free(k);
        return err;
    }

    memcpy(k, key, cache->key_size);
    memcpy(d, data, datasize);

    o->key = k;
    o->data = d;
    o->datasize = datasize;

    return 0;
}

static void
destroy_cache_obj(struct cache_obj *o)
{
    free((void *)(o->key));
    free((void *)(o->data));
}

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

    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    err = avl_tree_new(&ret->cache, sizeof(struct cache_obj *), &cache_obj_cmp,
                       0, NULL, ret, NULL);
    if (err)
        goto err1;

    err = avl_tree_new(&ret->trans, sizeof(struct op), &op_cmp, 0, NULL, ret,
                       NULL);
    if (err)
        goto err2;

    err = (*(cache_args->ops->create))(&ret->ctx, key_size, key_cmp,
                                       cache_args->args);
    if (err)
        goto err3;

    ret->ops = cache_args->ops;

    ret->trans_valid = 0;

    *ctx = ret;
    return 0;

err3:
    avl_tree_free(ret->trans);
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

    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    err = avl_tree_new(&ret->cache, sizeof(struct cache_obj *), &cache_obj_cmp,
                       0, NULL, ret, NULL);
    if (err)
        goto err1;

    err = avl_tree_new(&ret->trans, sizeof(struct op), &op_cmp, 0, NULL, ret,
                       NULL);
    if (err)
        goto err2;

    err = (*(cache_args->ops->open))(&ret->ctx, key_size, key_cmp,
                                     cache_args->args);
    if (err)
        goto err3;

    ret->ops = cache_args->ops;

    ret->trans_valid = 0;

    *ctx = ret;
    return 0;

err3:
    avl_tree_free(ret->trans);
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

    tmp = avl_tree_free(cache->trans);
    if (tmp != 0)
        err = tmp;

    free(cache);

    return err;
}

static int
fuse_cache_insert(void *ctx, const void *key, const void *data, size_t datasize)
{
    int err;
    struct cache_obj *o;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    o = do_malloc(sizeof(*o));
    if (o == NULL)
        return -errno;

    err = init_cache_obj(o, key, data, datasize, cache);
    if (err)
        goto err1;

    err = avl_tree_insert(cache->cache, &o);
    if (err)
        goto err2;

    err = (*(cache->ops->insert))(cache->ctx, key, data, datasize);
    if (err)
        goto err3;

    return 0;

err3:
    avl_tree_delete(cache->cache, &o);
err2:
    destroy_cache_obj(o);
err1:
    free(o);
    return err;
}

static int
fuse_cache_replace(void *ctx, const void *key, const void *data,
                   size_t datasize)
{
    int res;
    struct cache_obj *o, *o_old;
    struct cache_obj obj;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    obj.key = key;
    o = &obj;
    res = avl_tree_search(cache->cache, &o, &o_old);
    if (res != 1)
        return (res == 0) ? -EADDRNOTAVAIL : res;

    obj = *o_old;

    res = init_cache_obj(o_old, key, data, datasize, cache);
    if (res != 0)
        goto err1;

    res = (*(cache->ops->replace))(cache->ctx, key, data, datasize);
    if (res != 0)
        goto err2;

    return 0;

err2:
    destroy_cache_obj(o_old);
err1:
    *o_old = obj;
    return res;
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
    int err;
    struct cache_obj *o;
    struct cache_obj obj;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    err = (*(cache->ops->delete))(cache->ctx, key);
    if (err)
        return err;

    obj.key = key;
    o = &obj;
    if (avl_tree_delete(cache->cache, &o) != 0)
        abort();

    return 0;
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
