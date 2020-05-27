/*
 * obj.h
 */

#ifndef _OBJ_H
#define _OBJ_H

#include "config.h"

#include "util.h"

#include <limits.h>
#include <stdint.h>

enum db_obj_type {
    TYPE_HEADER = 1,
    TYPE_DIRENT,        /* look up by ino, name */
    TYPE_STAT,          /* look up by ino */
    TYPE_PAGE,          /* look up by ino, pgno */
    TYPE_XATTR,         /* look up by ino, name */
    TYPE_ULINKED_INODE, /* loop up by ino */
    TYPE_FREE_INO       /* look up by ino */
};

#define MAX_NAME (NAME_MAX+1)

struct db_key {
    enum db_obj_type    type;
    uint64_t            ino;
    uint64_t            pgno;
    char                name[MAX_NAME];
} __attribute__((packed));

struct disk_timespec {
    int32_t tv_sec;
    int32_t tv_nsec;
} __attribute__((packed));

/*
 * Format history:
 * - 1
 *   initial format
 * - 2
 *   changed page size from 128 kiB to 128 kiB - 64 B to reduce internal
 *   fragmentation
 * - 3
 *   modified I-node number allocation scheme to allow reusing I-node numbers
 *   by storing free I-node number information in bitmaps
 */
#define FMT_VERSION 3

struct db_obj_header {
    uint64_t    version;
    uint64_t    numinodes;
    uint8_t     reserved[112];
} __attribute__((packed));

#define FREE_INO_RANGE_SZ 2048

#define FREE_INO_LAST_USED 1 /* values in all following ranges are free */

struct db_obj_free_ino {
    uint64_t    used_ino[FREE_INO_RANGE_SZ/NBWD];
    uint8_t     flags;
} __attribute__((packed));

struct db_obj_dirent {
    uint64_t ino;
} __attribute__((packed));

struct db_obj_stat {
    uint64_t                st_dev;
    uint64_t                st_ino;
    uint32_t                st_mode;
    uint32_t                st_nlink;
    uint32_t                st_uid;
    uint32_t                st_gid;
    uint64_t                st_rdev;
    int64_t                 st_size;
    int64_t                 st_blksize;
    int64_t                 st_blocks;
#ifdef HAVE_STRUCT_STAT_ST_MTIMESPEC
    struct disk_timespec    st_atimespec;
    struct disk_timespec    st_mtimespec;
    struct disk_timespec    st_ctimespec;
#else
    struct disk_timespec    st_atim;
    struct disk_timespec    st_mtim;
    struct disk_timespec    st_ctim;
#endif
    uint32_t                num_ents;
} __attribute__((packed));

#endif

/* vi: set expandtab sw=4 ts=4: */
