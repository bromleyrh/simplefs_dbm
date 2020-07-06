/*
 * blkdev.h
 */

#ifndef _BLKDEV_H
#define _BLKDEV_H

struct fs_ops;

#define DB_HL_USEFSOPS 16

extern const struct fs_ops fs_blkdev_ops;
#define FS_BLKDEV_OPS ((void *)&fs_blkdev_ops)

#endif

/* vi: set expandtab sw=4 ts=4: */
