/*
 * back_end.c
 */

#include "back_end.h"
#include "common.h"
#include "util.h"

#include <errno.h>
#include <stdlib.h>

struct back_end {
    void                        *ctx;
    const struct back_end_ops   *ops;
    int                         abort_asserted;
};

struct back_end_iter {
    void            *ctx;
    struct back_end *be;
};

int
back_end_create(struct back_end **be, size_t key_size,
                const struct back_end_ops *ops, back_end_key_cmp_t key_cmp,
                void *args)
{
    int err;
    struct back_end *ret;

    if (oemalloc(&ret) == NULL)
        return MINUS_ERRNO;

    err = (*ops->create)(&ret->ctx, key_size, key_cmp, args);
    if (err) {
        free(ret);
        return err;
    }

    ret->ops = ops;

    ret->abort_asserted = 0;

    *be = ret;
    return 0;
}

int
back_end_open(struct back_end **be, size_t key_size,
              const struct back_end_ops *ops, back_end_key_cmp_t key_cmp,
              void *args)
{
    int err;
    struct back_end *ret;

    if (oemalloc(&ret) == NULL)
        return MINUS_ERRNO;

    err = (*ops->open)(&ret->ctx, key_size, key_cmp, args);
    if (err) {
        free(ret);
        return err;
    }

    ret->ops = ops;

    ret->abort_asserted = 0;

    *be = ret;
    return 0;
}

int
back_end_close(struct back_end *be)
{
    int err;

    err = (*be->ops->close)(be->ctx);

    free(be);

    return err;
}

int
back_end_insert(struct back_end *be, const void *key, const void *data,
                size_t datasize)
{
    return (*be->ops->insert)(be->ctx, key, data, datasize);
}

int
back_end_replace(struct back_end *be, const void *key, const void *data,
                 size_t datasize)
{
    return (*be->ops->replace)(be->ctx, key, data, datasize);
}

int
back_end_look_up(struct back_end *be, const void *key, void *retkey,
                 void *retdata, size_t *retdatasize, int look_up_nearest)
{
    return (*be->ops->look_up)(be->ctx, key, retkey, retdata, retdatasize,
                               look_up_nearest);
}

int
back_end_delete(struct back_end *be, const void *key)
{
    return (*be->ops->delete)(be->ctx, key);
}

int
back_end_walk(struct back_end *be, back_end_walk_cb_t fn, void *ctx)
{
    return (*be->ops->walk)(be->ctx, fn, ctx);
}

int
back_end_iter_new(struct back_end_iter **iter, struct back_end *be)
{
    int err;
    struct back_end_iter *ret;

    if (oemalloc(&ret) == NULL)
        return MINUS_ERRNO;

    err = (*be->ops->iter_new)(&ret->ctx, be->ctx);
    if (err) {
        free(ret);
        return err;
    }

    ret->be = be;

    *iter = ret;
    return 0;
}

int
back_end_iter_free(struct back_end_iter *iter)
{
    int err;

    err = (*iter->be->ops->iter_free)(iter->ctx);

    free(iter);

    return err;
}

int
back_end_iter_get(struct back_end_iter *iter, void *retkey, void *retdata,
                  size_t *retdatasize)
{
    return (*iter->be->ops->iter_get)(iter->ctx, retkey, retdata, retdatasize);
}

int
back_end_iter_next(struct back_end_iter *iter)
{
    return (*iter->be->ops->iter_next)(iter->ctx);
}

int
back_end_iter_search(struct back_end_iter *iter, const void *key)
{
    return (*iter->be->ops->iter_search)(iter->ctx, key);
}

int
back_end_trans_new(struct back_end *be)
{
    return (*be->ops->trans_new)(be->ctx);
}

int
back_end_trans_abort(struct back_end *be)
{
    int err;

    be->abort_asserted = 1;
    err = (*be->ops->trans_abort)(be->ctx);
    be->abort_asserted = 0;

    return err;
}

int
back_end_trans_commit(struct back_end *be)
{
    return (*be->ops->trans_commit)(be->ctx);
}

int
back_end_trans_abort_asserted(struct back_end *be)
{
    return be->abort_asserted;
}

int
back_end_sync(struct back_end *be)
{
    return (*be->ops->sync)(be->ctx);
}

int
back_end_ctl(struct back_end *be, int op, void *args)
{
    return (*be->ops->ctl)(be->ctx, op, args);
}

/* vi: set expandtab sw=4 ts=4: */
