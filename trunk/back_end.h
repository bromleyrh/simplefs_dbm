/*
 * back_end.h
 */

#ifndef _BACK_END_H
#define _BACK_END_H

#include <stddef.h>

#include <sys/types.h>

struct back_end;

struct back_end_iter;

typedef int (*back_end_key_cmp_t)(const void *k1, const void *k2,
                                  void *key_ctx);

typedef int (*back_end_walk_cb_t)(const void *key, const void *data,
                                  size_t datasize, void *ctx);

struct back_end_ops {
    int (*create)(void **ctx, size_t key_size, back_end_key_cmp_t key_cmp,
                  void *args);
    int (*open)(void **ctx, size_t key_size, back_end_key_cmp_t key_cmp,
                void *args);
    int (*close)(void *ctx);
    int (*insert)(void *ctx, const void *key, const void *data,
                  size_t datasize);
    int (*replace)(void *ctx, const void *key, const void *data,
                   size_t datasize);
    int (*look_up)(void *ctx, const void *key, void *retkey, void *retdata,
                   size_t *retdatasize, int look_up_nearest);
    int (*delete)(void *ctx, const void *key);
    int (*walk)(void *ctx, back_end_walk_cb_t fn, void *wctx);
    int (*iter_new)(void **iter, void *ctx);
    int (*iter_free)(void *iter);
    int (*iter_get)(void *iter, void *retkey, void *retdata,
                    size_t *retdatasize);
    int (*iter_next)(void *iter);
    int (*iter_search)(void *iter, const void *key);
    int (*trans_new)(void *ctx);
    int (*trans_abort)(void *ctx);
    int (*trans_commit)(void *ctx);
    int (*sync)(void *ctx);
    int (*ctl)(void *ctx, int op, void *args);
};

int back_end_create(struct back_end **be, size_t key_size,
                    const struct back_end_ops *ops, back_end_key_cmp_t key_cmp,
                    void *args);

int back_end_open(struct back_end **be, size_t key_size,
                  const struct back_end_ops *ops, back_end_key_cmp_t key_cmp,
                  void *args);

int back_end_close(struct back_end *be);

int back_end_insert(struct back_end *be, const void *key, const void *data,
                    size_t datasize);

int back_end_replace(struct back_end *be, const void *key, const void *data,
                     size_t datasize);

int back_end_look_up(struct back_end *be, const void *key, void *retkey,
                     void *retdata, size_t *retdatasize, int look_up_nearest);

int back_end_delete(struct back_end *be, const void *key);

int back_end_walk(struct back_end *be, back_end_walk_cb_t fn, void *ctx);

int back_end_iter_new(struct back_end_iter **iter, struct back_end *be);

int back_end_iter_free(struct back_end_iter *iter);

int back_end_iter_get(struct back_end_iter *iter, void *retkey, void *retdata,
                      size_t *retdatasize);

int back_end_iter_next(struct back_end_iter *iter);

int back_end_iter_search(struct back_end_iter *iter, const void *key);

int back_end_trans_new(struct back_end *be);

int back_end_trans_abort(struct back_end *be);

int back_end_trans_commit(struct back_end *be);

int back_end_sync(struct back_end *be);

int back_end_ctl(struct back_end *be, int op, void *args);

#endif

/* vi: set expandtab sw=4 ts=4: */
