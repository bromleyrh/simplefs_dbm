/*
 * back_end_dbm.h
 */

#ifndef _BACK_END_DBM_H
#define _BACK_END_DBM_H

#include "back_end.h"

#include <stdint.h>

#include <sys/types.h>

struct db_args {
    const char  *db_pathname;
    mode_t      db_mode;
    int         ro;
    void        (*trans_cb)(int trans_type, int act, int status, void *ctx);
    void        *trans_ctx;
    void        (*sync_cb)(int status, void *ctx);
    void        *sync_ctx;
    uint64_t    initusedbytes;
};

struct db_key_ctx {
    void    *last_key;
    int     last_key_valid;
};

struct db_alloc_cb {
    void (*alloc_cb)(uint64_t, int, void *);
    void *alloc_cb_ctx;
};

extern const struct back_end_ops back_end_dbm_ops;
#define BACK_END_DBM ((void *)&back_end_dbm_ops)

#define BACK_END_DBM_OP_FOREACH_ALLOC 1
#define BACK_END_DBM_OP_SET_ALLOC_HOOK 2

void back_end_dbm_disable_iter_commit(void *ctx);

#endif

/* vi: set expandtab sw=4 ts=4: */
