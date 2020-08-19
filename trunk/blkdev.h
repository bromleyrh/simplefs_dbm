/*
 * blkdev.h
 */

#ifndef _BLKDEV_H
#define _BLKDEV_H

#include <stdint.h>

struct fs_ops;

struct blkdev_args {
    uint64_t blkdevsz;
};

#define DB_HL_USEFSOPS 16

extern const struct fs_ops fs_blkdev_ops;
#define FS_BLKDEV_OPS ((void *)&fs_blkdev_ops)

#endif

/* vi: set expandtab sw=4 ts=4: */
