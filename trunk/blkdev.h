/*
 * blkdev.h
 */

#ifndef _BLKDEV_H
#define _BLKDEV_H

#include <stddef.h>
#include <stdint.h>

struct fs_ops;

struct blkdev_args {
    size_t      hdrlen;
    size_t      jlen;
    uint64_t    blkdevsz;
};

extern const struct fs_ops fs_blkdev_ops;
#define FS_BLKDEV_OPS (&fs_blkdev_ops)

#endif

/* vi: set expandtab sw=4 ts=4: */
