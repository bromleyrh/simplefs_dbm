/*
 * fuse_cache.h
 */

#ifndef _FUSE_CACHE_H
#define _FUSE_CACHE_H

#include "back_end.h"

struct fuse_cache;

struct fuse_cache_args {
    const struct back_end_ops   *ops;
    void                        (*set_trans_cb)(void *args,
                                                void (*cb)(int, int, int,
                                                           void *),
                                                void *ctx);
    void                        *args;
};

extern const struct back_end_ops back_end_fuse_cache_ops;
#define BACK_END_FUSE_CACHE ((void *)&back_end_fuse_cache_ops)

#endif

/* vi: set expandtab sw=4 ts=4: */
