/*
 * fuse_conn.c
 */

#include "fuse_conn.h"

#include <stdint.h>

#define FUSE_KERNEL_VERSION 7
#define FUSE_KERNEL_MINOR_VERSION 26

enum fuse_opcode {
    FUSE_LOOKUP         = 1,
    FUSE_FORGET         = 2,
    FUSE_GETATTR        = 3,
    FUSE_SETATTR        = 4,
    FUSE_READLINK       = 5,
    FUSE_SYMLINK        = 6,
    FUSE_MKNOD          = 8,
    FUSE_MKDIR          = 9,
    FUSE_UNLINK         = 10,
    FUSE_RMDIR          = 11,
    FUSE_RENAME         = 12,
    FUSE_LINK           = 13,
    FUSE_OPEN           = 14,
    FUSE_READ           = 15,
    FUSE_WRITE          = 16,
    FUSE_STATFS         = 17,
    FUSE_RELEASE        = 18,
    FUSE_FSYNC          = 20,
    FUSE_SETXATTR       = 21,
    FUSE_GETXATTR       = 22,
    FUSE_LISTXATTR      = 23,
    FUSE_REMOVEXATTR    = 24,
    FUSE_FLUSH          = 25,
    FUSE_INIT           = 26,
    FUSE_OPENDIR        = 27,
    FUSE_READDIR        = 28,
    FUSE_RELEASEDIR     = 29,
    FUSE_FSYNCDIR       = 30,
    FUSE_GETLK          = 31,
    FUSE_SETLK          = 32,
    FUSE_SETLKW         = 33,
    FUSE_ACCESS         = 34,
    FUSE_CREATE         = 35,
    FUSE_INTERRUPT      = 36,
    FUSE_BMAP           = 37,
    FUSE_DESTROY        = 38,
    FUSE_IOCTL          = 39,
    FUSE_POLL           = 40,
    FUSE_NOTIFY_REPLY   = 41,
    FUSE_BATCH_FORGET   = 42,
    FUSE_FALLOCATE      = 43,
    FUSE_READDIRPLUS    = 44,
    FUSE_RENAME2        = 45,
    FUSE_LSEEK          = 46
};

#define FUSE_ROOT_ID 1

struct fuse_attr {
    uint64_t ino;
    uint64_t size;
    uint64_t blocks;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint32_t atimensec;
    uint32_t mtimensec;
    uint32_t ctimensec;
    uint32_t mode;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint32_t rdev;
    uint32_t blksize;
    uint32_t padding;
};

struct fuse_kstatfs {
    uint64_t blocks;
    uint64_t bfree;
    uint64_t bavail;
    uint64_t files;
    uint64_t ffree;
    uint32_t bsize;
    uint32_t namelen;
    uint32_t frsize;
    uint32_t padding;
    uint32_t spare[6];
};

struct fuse_in_header {
    uint32_t    len;
    uint32_t    opcode;
    uint64_t    unique;
    uint64_t    nodeid;
    uint32_t    uid;
    uint32_t    gid;
    uint32_t    pid;
    uint32_t    padding;
    uint8_t     data[0];
};

struct fuse_out_header {
    uint32_t    len;
    int32_t     error;
    uint64_t    unique;
    uint8_t     data[0];
};

#define FUSE_ASYNC_READ              1
#define FUSE_POSIX_LOCKS             2
#define FUSE_FILE_OPS                4
#define FUSE_ATOMIC_O_TRUNC          8
#define FUSE_EXPORT_SUPPORT         16
#define FUSE_BIG_WRITES             32
#define FUSE_DONT_MASK              64
#define FUSE_SPLICE_WRITE          128
#define FUSE_SPLICE_MOVE           256
#define FUSE_SPLICE_READ           512
#define FUSE_FLOCK_LOCKS          1024
#define FUSE_HAS_IOCTL_DIR        2048
#define FUSE_AUTO_INVAL_DATA      4096
#define FUSE_DO_READDIRPLUS       8192
#define FUSE_ASYNC_DIO           16384
#define FUSE_WRITEBACK_CACHE     32768
#define FUSE_NO_OPEN_SUPPORT     65536
#define FUSE_PARALLEL_DIROPS    131072
#define FUSE_HANDLE_KILLPRIV    262144
#define FUSE_POSIX_ACL          524288

struct fuse_init_in {
    uint32_t major;
    uint32_t minor;
    uint32_t max_readahead;
    uint32_t flags;
};

struct fuse_init_out {
    uint32_t major;
    uint32_t minor;
    uint32_t max_readahead;
    uint32_t flags;
    uint16_t max_background;
    uint16_t congestion_threshold;
    uint32_t max_write;
    uint32_t time_gran;
    uint32_t unused[9];
};

struct fuse_entry_out {
    uint64_t            nodeid;
    uint64_t            generation;
    uint64_t            entry_valid;
    uint64_t            attr_valid;
    uint32_t            entry_valid_nsec;
    uint32_t            attr_valid_nsec;
    struct fuse_attr    attr;
};

#define FUSE_GETATTR_FH 1

struct fuse_getattr_in {
    uint32_t getattr_flags;
    uint32_t dummy;
    uint64_t fh;
};

struct fuse_attr_out {
    uint64_t            attr_valid;
    uint32_t            attr_valid_nsec;
    uint32_t            dummy;
    struct fuse_attr    attr;
};

struct fuse_access_in {
    uint32_t mask;
    uint32_t padding;
};

struct fuse_open_in {
    uint32_t flags;
    uint32_t unused;
};

#define FOPEN_DIRECT_IO     1
#define FOPEN_KEEP_CACHE    2
#define FOPEN_NONSEEKABLE   4

struct fuse_open_out {
    uint64_t fh;
    uint32_t open_flags;
    uint32_t padding;
};

struct fuse_flush_in {
    uint64_t fh;
    uint32_t unused;
    uint32_t padding;
    uint64_t lock_owner;
};

#define FUSE_RELEASE_FLUSH          1
#define FUSE_RELEASE_FLOCK_UNLOCK   2

struct fuse_release_in {
    uint64_t fh;
    uint32_t flags;
    uint32_t release_flags;
    uint64_t lock_owner;
};

#define FUSE_READ_LOCKOWNER 2

#define FUSE_MIN_READ_BUFFER 8192

struct fuse_read_in {
    uint64_t fh;
    uint64_t offset;
    uint32_t size;
    uint32_t read_flags;
    uint64_t lock_owner;
    uint32_t flags;
    uint32_t padding;
};

struct fuse_statfs_out {
    struct fuse_kstatfs st;
};

struct fuse_interrupt_in {
    uint64_t unique;
};

/* vi: set expandtab sw=4 ts=4: */
