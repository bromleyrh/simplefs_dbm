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
                                  struct back_end_key_ctx *key_ctx);

struct back_end_key_ctx {
    void    *last_key;
    int     last_key_valid;
};

struct db_args {
    const char  *db_pathname;
    mode_t      db_mode;
};

int back_end_create(struct back_end **be, size_t key_size,
                    back_end_key_cmp_t key_cmp, void *args);

int back_end_open(struct back_end **be, size_t key_size,
                  back_end_key_cmp_t key_cmp, void *args);

int back_end_close(struct back_end *be);

int back_end_insert(struct back_end *be, const void *key, const void *data,
                    size_t datasize);

int back_end_look_up(struct back_end *be, const void *key, void *retdata);

int back_end_iter_new(struct back_end_iter **iter, struct back_end *be);

int back_end_iter_free(struct back_end_iter *iter);

int back_end_iter_get(struct back_end_iter *iter, void *retdata);

int back_end_iter_next(struct back_end_iter *iter);

int back_end_iter_search(struct back_end_iter *iter, const void *key);

int back_end_trans_new(struct back_end *be);

int back_end_trans_abort(struct back_end *be);

int back_end_trans_commit(struct back_end *be);

#endif

/* vi: set expandtab sw=4 ts=4: */
