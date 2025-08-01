/*
 * ops.c
 *
 * Note: All of the requests handled by simplefs are uninterruptible to simplify
 * error handling. Checks for the -ENOENT error return from reply_*() are added
 * for robustness, but this condition should never occur.
 */

#include "config.h"

#include "back_end.h"
#include "back_end_dbm.h"
#include "common.h"
#include "compat.h"
#include "file_tab.h"
#include "fuse_cache.h"
#include "obj.h"
#include "ops.h"
#include "request.h"
#include "simplefs.h"
#include "sys_dep.h"
#include "util.h"

#include <arithmetic.h>
#include <avl_tree.h>
#include <fifo.h>
#include <packing.h>
#include <strings_ext.h>

#include <files/acc_ctl.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

struct ref_inodes {
    struct avl_tree *ref_inodes;
    pthread_mutex_t ref_inodes_mtx;
};

struct fspriv {
    struct back_end     *be;
    struct fifo         *queue;
    pthread_t           worker_td;
    int                 worker_td_status;
    int                 blkdev;
    uint64_t            blkdevsz;
    inum_t              root_id;
    struct file_tab     *ftab;
    struct ref_inodes   ref_inodes;
    int                 wb_err;
};

struct queue_elem {
    int             (*op)(void *);
    void            *args;
    pthread_mutex_t mtx;
    pthread_cond_t  cv;
    int             ret;
};

struct ref_ino {
    inum_t      ino;
    uint64_t    nlink;
    uint64_t    refcnt;
    uint64_t    nlookup;
    int         nodelete;
};

struct op_args {
    void                    *req;
    const struct ctx        *ctx;
    struct back_end         *be;
    int                     ro;
    inum_t                  root_id;
    struct ref_inodes       *ref_inodes;
    struct ref_ino          *refinop[4];
    inum_t                  ino;
    struct db_key           k;
    struct db_obj_header    hdr;
    struct db_obj_stat      s;
    struct stat             attr;
    union {
        int                 inc_lookup_cnt; /* lookup() */
        uint64_t            nlookup;        /* forget() */
        int                 to_set;         /* setattr() */
        struct {
            inum_t          parent;
            const char      *name;
            dev_t           rdev;
            mode_t          mode;
            const char      *link;
        } mknod_data;                       /* create(), mkdir(), symlink(),
                                               mknod() */
        struct {
            inum_t          parent;
            const char      *name;
            inum_t          newparent;
            const char      *newname;
        } link_data;                        /* link(), rename(), unlink(),
                                               rmdir() */
        struct {
            off_t           off;
            size_t          size;
            char            *a_rd;
            const char      *a_wr;
            struct iovec    *iov;
            int             count;
        } rdwr_data;                        /* read(), write(), readlink() */
        struct {
            struct open_dir *odir;
            char            *buf;
            size_t          bufsize;
            size_t          buflen;
        } readdir_data;                     /* readdir() */
        struct {
            const char      *name;
            char            *value_a_rd;
            const char      *value_a_wr;
            size_t          size;
            int             flags;
        } xattr_data;                       /* setxattr(), getxattr(),
                                               listxattr(), removexattr() */
        int                 mask;           /* access() */
    } op_data;
};

struct open_dir {
    char    cur_name[NAME_MAX+1];
    off_t   off;
    inum_t  ino;
};

struct open_file {
    inum_t ino;
};

struct free_ref_inodes_ctx {
    struct fspriv   *priv;
    int             nowrite;
    int             err;
};

struct space_alloc_ctx {
    int64_t delta;
};

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

#ifndef HAVE_SYS_XATTR_H
#define XATTR_CREATE 1
#define XATTR_REPLACE 2
#endif

#define SIMPLEFS_MOUNT_PIPE_MSG_OK "1"

#define ALL_PERMS (S_ISUID | S_ISGID | S_ISVTX | ACC_MODE_ACCESS_PERMS)

#define DB_PATHNAME "fs.db"

#define OP_RET_NONE INT_MAX

#define DB_OBJ_MAX_SIZE sizeof(struct db_obj_stat)

#define NAME_CUR_DIR "."
#define NAME_PARENT_DIR ".."

#define CACHE_TIMEOUT 1800.0
#define KEEP_CACHE_OPEN 1

#ifndef OFF_MAX
#define OFF_MAX INT64_MAX
#endif

#define UNREF_MAX INT32_MAX

#define ROOT_DIR_INIT_PERMS S_IRWXU

#if 0 && !defined(NDEBUG)
#define DEBUG_DUMP
#endif

static const char null_data[PG_SIZE];

#define ASSERT_UNDER_TRANS(be) (assert(back_end_trans_new(be) == -EBUSY))

#define _packed_st_tim(s, which) \
    (struct disk_timespec *)packed_memb_addr(db_obj_stat, s, which)

#define packed_st_tim(s, which) _packed_st_tim(s, st_##which##tim)

static int uint64_cmp(uint64_t, uint64_t);

static int db_key_cmp(const void *, const void *, void *);

static void *worker_td(void *);
static int do_queue_op(struct fspriv *, int (*)(void *), void *);
static int join_worker(struct fspriv *);

static void sync_cb(int, void *);

static void dump_db_obj(FILE *, const void *, const void *, size_t,
                        const char *, void *);
#ifdef DEBUG_DUMP
static int dump_cb(const void *, const void *, size_t, void *);
#endif
static int dump_db(struct back_end *);

static int ref_inode_cmp(const void *, const void *, void *);

static inum_t free_ino_find(uint64_t *, inum_t);
static int get_ino(struct back_end *, inum_t *);
static int release_ino(struct back_end *, inum_t, inum_t);

static uint64_t adj_refcnt(uint64_t *, int32_t);
static int unref_inode(struct back_end *, inum_t, struct ref_inodes *,
                       struct ref_ino *, int32_t, int32_t, int32_t, int *);
static int free_ref_inodes_cb(const void *, void *);

static int inc_refcnt(struct back_end *, struct ref_inodes *, inum_t, int32_t,
                      int32_t, int32_t, struct ref_ino **);
static int dec_refcnt(struct ref_inodes *, int32_t, int32_t, int32_t,
                      struct ref_ino *);
static int set_ref_inode_nodelete(struct back_end *, inum_t,
                                  struct ref_inodes *, inum_t, int);

static int remove_ulinked_nodes(struct back_end *, inum_t);

static void do_set_ts(struct disk_timespec *, struct utim *);
static void set_ts(struct disk_timespec *, struct disk_timespec *,
                   struct disk_timespec *);
static void deserialize_ts(struct utim *, struct disk_timespec *);

static void deserialize_stat(struct stat *, struct db_obj_stat *);

static int add_xattr_name(char **, size_t *, size_t *, const char *);

static int truncate_file(struct back_end *, inum_t, off_t, off_t, uint64_t *);
static int delete_file(struct back_end *, inum_t, inum_t);

static void free_iov(struct iovec *, int);

static int new_node(struct back_end *, struct ref_inodes *, inum_t,
                    const char *, uid_t, gid_t, mode_t, dev_t, off_t,
                    struct stat *, struct ref_ino **, int);

static int new_node_link(struct back_end *, struct ref_inodes *, inum_t, inum_t,
                         const char *, struct ref_ino **);
static int rem_node_link(struct back_end *, inum_t, struct ref_inodes *,
                         inum_t, inum_t, const char *, int *,
                         struct ref_ino **);

static int new_dir(struct back_end *, inum_t, struct ref_inodes *, inum_t,
                   const char *, uid_t, gid_t, mode_t, struct stat *,
                   struct ref_ino **, int);
static int rem_dir(struct back_end *, inum_t, struct ref_inodes *, inum_t,
                   inum_t, const char *, int, int);

static int new_dir_link(struct back_end *, struct ref_inodes *, inum_t, inum_t,
                        const char *, struct ref_ino **);
static int rem_dir_link(struct back_end *, inum_t, struct ref_inodes *, inum_t,
                        inum_t, const char *, struct ref_ino **);

static void space_alloc_cb(uint64_t, int, void *);
static int space_alloc_set_hook(struct back_end *,
                                void (*)(uint64_t, int, void *), void *);

static int space_alloc_init_op(struct space_alloc_ctx *, struct back_end *);
static int space_alloc_abort_op(struct back_end *);
static int space_alloc_finish_op(struct space_alloc_ctx *, struct back_end *);

static int do_look_up(void *);
static int do_setattr(void *);
static int do_read_symlink(void *);
static int do_forget(void *);
static int do_create_node(void *);
static int do_create_dir(void *);
static int do_remove_node_link(void *);
static int do_remove_dir(void *);
static int do_create_symlink(void *);
static int do_rename(void *);
static int do_create_node_link(void *);
static int do_read_entries(void *);
static int do_open(void *);
static int do_read_data(void *);
static int do_write_data(void *);
static int do_close(void *);
static int do_sync(void *);
static int do_read_header(void *);
static int do_setxattr(void *);
static int do_getxattr(void *);
static int do_listxattr(void *);
static int do_removexattr(void *);
static int do_access(void *);
static int do_create(void *);

static void simplefs_lookup(void *, inum_t, const char *);
static void simplefs_forget(void *, inum_t, uint64_t);
static void simplefs_getattr(void *, inum_t, struct file_info *);
static void simplefs_setattr(void *, inum_t, struct stat *, int,
                             struct file_info *);
static void simplefs_readlink(void *, inum_t);
static void simplefs_mknod(void *, inum_t, const char *, mode_t, dev_t);
static void simplefs_mkdir(void *, inum_t, const char *, mode_t);
static void simplefs_unlink(void *, inum_t, const char *);
static void simplefs_rmdir(void *, inum_t, const char *);
static void simplefs_symlink(void *, const char *, inum_t, const char *);
static void simplefs_rename(void *, inum_t, const char *, inum_t, const char *);
static void simplefs_link(void *, inum_t, inum_t, const char *);
static void simplefs_open(void *, inum_t, struct file_info *);
static void simplefs_read(void *, inum_t, size_t, off_t, struct file_info *);
static void simplefs_write(void *, inum_t, const char *, size_t, off_t,
                           struct file_info *);
static void simplefs_flush(void *, inum_t, struct file_info *);
static void simplefs_opendir(void *, inum_t, struct file_info *);
static void simplefs_readdir(void *, inum_t, size_t, off_t, struct file_info *);
static void simplefs_release(void *, inum_t, struct file_info *);
static void simplefs_fsync(void *, inum_t, int, struct file_info *);
static void simplefs_releasedir(void *, inum_t, struct file_info *);
static void simplefs_fsyncdir(void *, inum_t, int, struct file_info *);
static void simplefs_statfs(void *, inum_t);
static void simplefs_setxattr(void *, inum_t, const char *, const char *,
                              size_t, int);
static void simplefs_getxattr(void *, inum_t, const char *, size_t);
static void simplefs_listxattr(void *, inum_t, size_t);
static void simplefs_removexattr(void *, inum_t, const char *);
static void simplefs_access(void *, inum_t, int);
static void simplefs_create(void *, inum_t, const char *, mode_t,
                            struct file_info *);
static void simplefs_fallocate(void *, inum_t, int, off_t, off_t,
                               struct file_info *);

static int
uint64_cmp(uint64_t n1, uint64_t n2)
{
    return (n1 > n2) - (n1 < n2);
}

static int
db_key_cmp(const void *k1, const void *k2, void *key_ctx)
{
    const struct db_key *key1 = k1;
    const struct db_key *key2 = k2;
    int cmp;
    uint32_t type;

    if (key_ctx != NULL) {
        struct db_key_ctx *ctx = key_ctx;

        memcpy(ctx->last_key, k2, sizeof(struct db_key));
        ctx->last_key_valid = 1;
    }

    type = unpack_u32(db_key, key1, type);

    cmp = uint64_cmp(type, unpack_u32(db_key, key2, type));
    if (cmp != 0 || type == TYPE_HEADER)
        return cmp;

    cmp = uint64_cmp(unpack_u64(db_key, key1, ino),
                     unpack_u64(db_key, key2, ino));
    if (cmp != 0)
        return cmp;

    switch (type) {
    case TYPE_DIRENT:
    case TYPE_XATTR:
        cmp = strcmp(packed_memb_addr(db_key, key1, name),
                     packed_memb_addr(db_key, key2, name));
        break;
    case TYPE_PAGE:
        cmp = uint64_cmp(unpack_u64(db_key, key1, pgno),
                         unpack_u64(db_key, key2, pgno));
    case TYPE_FREE_INO:
    case TYPE_STAT:
    case TYPE_ULINKED_INODE:
        break;
    default:
        errmsgf("Unrecognized object type %" PRIu32 " in %s()\n", type,
                __func__);
        abort();
    }

    return cmp;
}

static void *
worker_td(void *args)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = args;
    struct queue_elem *op;

    priv = md->priv;

    for (;;) {
        ret = fifo_get(priv->queue, &op);
        if (ret != 0) {
            /* FIXME: In this unlikely case, worker_td() will return without
             * preventing further calls to do_queue_op() or waking up threads
             * currently blocked in do_queue_op(). This will result in a stalled
             * file system. */
            break;
        }
        if (op->op == NULL)
            break;

        ret = (*op->op)(op->args);

        pthread_mutex_lock(&op->mtx);
        op->ret = ret;
        pthread_cond_broadcast(&op->cv);
        pthread_mutex_unlock(&op->mtx);
    }

    priv->worker_td_status = ret;

    return args;
}

static int
do_queue_op(struct fspriv *fspriv, int (*op_fn)(void *), void *args)
{
    int err;
    struct queue_elem op, *opp;

    err = -pthread_mutex_init(&op.mtx, NULL);
    if (err)
        return err;

    err = -pthread_cond_init(&op.cv, NULL);
    if (err)
        goto err1;

    op.op = op_fn;
    op.args = args;
    op.ret = OP_RET_NONE;

    opp = &op;
    err = fifo_put(fspriv->queue, &opp);
    if (err)
        goto err2;

    pthread_mutex_lock(&op.mtx);
    while (op.ret == OP_RET_NONE)
        pthread_cond_wait(&op.cv, &op.mtx);
    pthread_mutex_unlock(&op.mtx);

    pthread_mutex_destroy(&op.mtx);
    pthread_cond_destroy(&op.cv);

    return op.ret;

err2:
    pthread_cond_destroy(&op.cv);
err1:
    pthread_mutex_destroy(&op.mtx);
    return err;
}

static int
join_worker(struct fspriv *priv)
{
    int err;
    struct queue_elem op, *opp;

    op.op = NULL;
    opp = &op;
    err = fifo_put(priv->queue, &opp);
    if (err)
        return err;

    err = -pthread_join(priv->worker_td, NULL);

    return err ? err : priv->worker_td_status;
}

static void
sync_cb(int status, void *ctx)
{
    struct fspriv *priv = ctx;

    /* FIXME: review this code */
    if (!back_end_trans_abort_asserted(priv->be)) /* abort generated by DBM */
        priv->wb_err = status < 0 ? status : 0;
}

static void
dump_db_obj(FILE *f, const void *key, const void *data, size_t datasize,
            const char *prefix, void *ctx)
{
    const struct db_key *k = key;
    const union {
        struct db_obj_dirent    de;
        struct db_obj_header    hdr;
        struct db_obj_stat      s;
    } *d;
    uint32_t type;
    uint64_t ino;

    (void)ctx;

    fputs(prefix, f);

    type = unpack_u32(db_key, k, type);
    if (type != TYPE_HEADER)
        ino = unpack_u64(db_key, k, ino);

    d = data;

    switch (type) {
    case TYPE_HEADER:
        assert(datasize == sizeof(d->hdr));

        fprintf(f, "Header: I-node count %" PRIu64 "\n",
                unpack_u64(db_obj_header, &d->hdr, numinodes));
        break;
    case TYPE_FREE_INO:
        fprintf(f, "Free I-node number information: number %" PRIu64 " to %"
                   PRIu64 "\n",
                ino, ino + FREE_INO_RANGE_SZ - 1);
        break;
    case TYPE_DIRENT:
        assert(datasize == sizeof(d->de));

        fprintf(f, "Directory entry: directory %" PRIu64 ", name %s -> node %"
                   PRIu64 "\n",
                ino, (char *)packed_memb_addr(db_key, k, name),
                unpack_u64(db_obj_dirent, &d->de, ino));
        break;
    case TYPE_STAT:
        assert(datasize == sizeof(d->s));

        fprintf(f, "I-node entry: node %" PRIu64 " -> st_ino %" PRIu64 "\n",
                ino, unpack_u64(db_obj_stat, &d->s, st_ino));
        break;
    case TYPE_PAGE:
        fprintf(f, "Page: node %" PRIu64 ", page %" PRIu64 ", size %zu\n",
                ino, unpack_u64(db_key, k, pgno), datasize);
        break;
    case TYPE_XATTR:
        fprintf(f, "Extended attribute entry: node %" PRIu64 ", name %s, "
                   "size %zu\n",
                ino, (char *)packed_memb_addr(db_key, k, name), datasize);
        break;
    case TYPE_ULINKED_INODE:
        fprintf(f, "Unlinked I-node entry: node %" PRIu64 "\n",
                ino);
        break;
    default:
        errmsgf("Unrecognized object type %" PRIu32 " in %s()\n", type,
                __func__);
        abort();
    }
}

#ifdef DEBUG_DUMP
static int
dump_cb(const void *key, const void *data, size_t datasize, void *ctx)
{
    (void)ctx;

    dump_db_obj(stderr, key, data, datasize, "", NULL);

    return 0;
}

#endif

static int
dump_db(struct back_end *be)
{
#ifdef DEBUG_DUMP
    return back_end_walk(be, &dump_cb, NULL);
#else
    (void)be;

    return 0;
#endif
}

static int
ref_inode_cmp(const void *k1, const void *k2, void *ctx)
{
    struct ref_ino *ino1 = *(struct ref_ino *const *)k1;
    struct ref_ino *ino2 = *(struct ref_ino *const *)k2;

    (void)ctx;

    return uint64_cmp(ino1->ino, ino2->ino);
}

void
used_ino_set(uint64_t *used_ino, inum_t base, inum_t ino, int val)
{
    int idx, wordidx;
    uint64_t mask;

    idx = ino - base;
    wordidx = idx / NBWD;
    mask = UINT64_C(1) << idx % NBWD;

    if (val)
        used_ino[wordidx] |= mask;
    else
        used_ino[wordidx] &= ~mask;
}

static inum_t
free_ino_find(uint64_t *used_ino, inum_t base)
{
    int idx;
    int maxidx;
    inum_t ino;
    static const uint64_t filled = ~UINT64_C(0);
    uint64_t word;

    maxidx = FREE_INO_RANGE_SZ / NBWD - 1;
    for (idx = 0;; idx++) {
        if (used_ino[idx] != filled)
            break;
        if (idx == maxidx)
            return 0;
    }
    ino = base + idx * NBWD;
    word = ~used_ino[idx];

    idx = 0;
    if (!(word & 0xffffffff)) {
        word >>= 32;
        idx += 32;
    }
    if (!(word & 0xffff)) {
        word >>= 16;
        idx += 16;
    }
    if (!(word & 0xff)) {
        word >>= 8;
        idx += 8;
    }
    if (!(word & 0xf)) {
        word >>= 4;
        idx += 4;
    }
    if (!(word & 0x3)) {
        word >>= 2;
        idx += 2;
    }
    if (!(word & 0x1))
        idx += 1;

    return ino + idx;
}

static int
get_ino(struct back_end *be, inum_t *ino)
{
    int res;
    inum_t ret;
    struct back_end_iter *iter;
    struct db_key k;
    struct db_obj_free_ino freeino;
    struct db_obj_header hdr;
    struct db_obj_stat s;
    uint64_t *freeino_used_ino;
    uint64_t k_ino;

    res = back_end_iter_new(&iter, be);
    if (res != 0)
        return res;

    pack_u32(db_key, &k, type, TYPE_FREE_INO);
    pack_u64(db_key, &k, ino, 0);
    res = back_end_iter_search(iter, &k);
    if (res < 0) {
        back_end_iter_free(iter);
        return res;
    }

    res = back_end_iter_get(iter, &k, &freeino, NULL);
    back_end_iter_free(iter);
    if (res != 0)
        return res == -EADDRNOTAVAIL ? -ENOSPC : res;
    if (unpack_u32(db_key, &k, type) != TYPE_FREE_INO)
        return -ENOSPC;

    k_ino = unpack_u64(db_key, &k, ino);
    freeino_used_ino = (uint64_t *)packed_memb_addr(db_obj_free_ino, &freeino,
                                                    used_ino);

    ret = free_ino_find(freeino_used_ino, k_ino);
    if (ret == 0) {
        if (!(unpack_u8(db_obj_free_ino, &freeino, flags) & FREE_INO_LAST_USED))
            return -EILSEQ;
        if (ULONG_MAX - k_ino < FREE_INO_RANGE_SZ)
            return -ENOSPC;

        res = back_end_delete(be, &k);
        if (res != 0)
            return res;

        k_ino += FREE_INO_RANGE_SZ;
        pack_u64(db_key, &k, ino, k_ino);
        memset(freeino_used_ino, 0,
               packed_memb_size(db_obj_free_ino, used_ino));
        used_ino_set(freeino_used_ino, k_ino, k_ino, 1);
        pack_u8(db_obj_free_ino, &freeino, flags, FREE_INO_LAST_USED);
        res = back_end_insert(be, &k, &freeino, sizeof(freeino));
        if (res != 0)
            return res;

        *ino = k_ino;
        return 0;
    }

    used_ino_set(freeino_used_ino, k_ino, ret, 1);
    res = memcchr(freeino_used_ino, 0xff,
                  packed_memb_size(db_obj_free_ino, used_ino))
          == NULL
          && !(unpack_u8(db_obj_free_ino, &freeino, flags) & FREE_INO_LAST_USED)
          ? back_end_delete(be, &k)
          : back_end_replace(be, &k, &freeino, sizeof(freeino));
    if (res != 0)
        return res;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, ret);
    res = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (res != 0)
        return res == 1 ? -EIO : res;

    pack_u32(db_key, &k, type, TYPE_HEADER);
    res = back_end_look_up(be, &k, NULL, &hdr, NULL, 0);
    if (res != 1)
        return res == 0 ? -EILSEQ : res;

    pack_u64(db_obj_header, &hdr, numinodes,
             unpack_u64(db_obj_header, &hdr, numinodes) + 1);
    res = back_end_replace(be, &k, &hdr, sizeof(hdr));
    if (res != 0)
        return res;

    *ino = ret;
    return 0;
}

static int
release_ino(struct back_end *be, inum_t root_id, inum_t ino)
{
    int res;
    struct db_key k;
    struct db_obj_free_ino freeino;
    struct db_obj_header hdr;
    uint64_t *freeino_used_ino;
    uint64_t k_ino;

    k_ino = (ino - root_id) / FREE_INO_RANGE_SZ * FREE_INO_RANGE_SZ + root_id;
    freeino_used_ino = (uint64_t *)packed_memb_addr(db_obj_free_ino, &freeino,
                                                    used_ino);

    pack_u32(db_key, &k, type, TYPE_FREE_INO);
    pack_u64(db_key, &k, ino, k_ino);
    res = back_end_look_up(be, &k, &k, &freeino, NULL, 0);
    if (res != 1) {
        if (res != 0)
            return res;

        /* insert new free I-node number information object */
        memset(freeino_used_ino, 0xff,
               packed_memb_size(db_obj_free_ino, used_ino));
        used_ino_set(freeino_used_ino, k_ino, ino, 0);
        pack_u8(db_obj_free_ino, &freeino, flags, 0);
        res = back_end_insert(be, &k, &freeino, sizeof(freeino));
        if (res != 0)
            return res;
    } else {
        used_ino_set(freeino_used_ino, k_ino, ino, 0);
        res = back_end_replace(be, &k, &freeino, sizeof(freeino));
        if (res != 0)
            return res;
    }

    pack_u32(db_key, &k, type, TYPE_HEADER);
    res = back_end_look_up(be, &k, NULL, &hdr, NULL, 0);
    if (res != 1)
        return res == 0 ? -EILSEQ : res;

    pack_u64(db_obj_header, &hdr, numinodes,
             unpack_u64(db_obj_header, &hdr, numinodes) - 1);
    return back_end_replace(be, &k, &hdr, sizeof(hdr));
}

static uint64_t
adj_refcnt(uint64_t *refcnt, int32_t delta)
{
    if (delta != 0)
        *refcnt = delta == -INT_MAX ? 0 : *refcnt + delta;

    return *refcnt;
}

/*
 * This function must be called under a transaction to allow cancelling changes
 * in case of an error, unless nlink is 0.
 */
static int
unref_inode(struct back_end *be, inum_t root_id, struct ref_inodes *ref_inodes,
            struct ref_ino *ino, int32_t nlink, int32_t nref, int32_t nlookup,
            int *deleted)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    uint64_t nlinkp, refcntp, nlookupp;

    if (nlink != 0) {
        pack_u32(db_key, &k, type, TYPE_STAT);
        pack_u64(db_key, &k, ino, ino->ino);
        ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
        if (ret != 1)
            return ret == 0 ? -ENOENT : ret;
    }

    pthread_mutex_lock(&ref_inodes->ref_inodes_mtx);
    nlinkp = adj_refcnt(&ino->nlink, nlink);
    refcntp = adj_refcnt(&ino->refcnt, nref);
    nlookupp = adj_refcnt(&ino->nlookup, nlookup);
    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);

    if (nlinkp == 0 && refcntp == 0 && nlookupp == 0) {
        ret = delete_file(be, root_id, ino->ino);
        if (ret == 0 && deleted != NULL)
            *deleted = 1;
        return ret;
    }

    if (nlink != 0) {
        ASSERT_UNDER_TRANS(be);

        pack_u32(db_obj_stat, &s, st_nlink, nlinkp);
        assert(unpack_u64(db_obj_stat, &s, st_ino)
               == unpack_u64(db_key, &k, ino));
        ret = back_end_replace(be, &k, &s, sizeof(s));
        if (ret != 0)
            return ret;
    }

    if (deleted != NULL)
        *deleted = 0;
    return 0;
}

static int
free_ref_inodes_cb(const void *keyval, void *ctx)
{
    int err;
    struct free_ref_inodes_ctx *fctx = ctx;
    struct fspriv *priv = fctx->priv;
    struct ref_ino *ino = *(struct ref_ino *const *)keyval;

    if (fctx->nowrite) {
        err = unref_inode(priv->be, priv->root_id, &priv->ref_inodes, ino, 0,
                          -INT_MAX, -INT_MAX, NULL);
        if (err)
            goto err1;
    } else {
        struct space_alloc_ctx sctx;

        err = back_end_trans_new(priv->be);
        if (err)
            goto err1;

        err = space_alloc_init_op(&sctx, priv->be);
        if (err)
            goto err2;

        err = unref_inode(priv->be, priv->root_id, &priv->ref_inodes, ino, 0,
                          -INT_MAX, -INT_MAX, NULL);
        if (err)
            goto err3;

        err = space_alloc_finish_op(&sctx, priv->be);
        if (err)
            goto err2;

        err = back_end_trans_commit(priv->be);
        if (err)
            goto err2;
    }

    free(ino);

    return 0;

err3:
    space_alloc_abort_op(priv->be);
err2:
    back_end_trans_abort(priv->be);
err1:
    fctx->err = err;
    free(ino);
    return 0;
}

static int
inc_refcnt(struct back_end *be, struct ref_inodes *ref_inodes, inum_t ino,
           int32_t nlink, int32_t nref, int32_t nlookup, struct ref_ino **inop)
{
    int ret;
    struct ref_ino refino, *refinop = NULL;

    pthread_mutex_lock(&ref_inodes->ref_inodes_mtx);

    refino.ino = ino;
    refinop = &refino;

    ret = avl_tree_search(ref_inodes->ref_inodes, &refinop, &refinop);
    if (ret == 1) {
        adj_refcnt(&refinop->nlink, nlink);
        adj_refcnt(&refinop->refcnt, nref);
        adj_refcnt(&refinop->nlookup, nlookup);
    } else {
        struct db_key k;
        struct db_obj_stat s;

        if (oemalloc(&refinop) == NULL) {
            ret = MINUS_ERRNO;
            goto err1;
        }

        pack_u32(db_key, &k, type, TYPE_STAT);
        pack_u64(db_key, &k, ino, ino);
        ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
        if (ret != 1) {
            if (ret == 0)
                ret = -ENOENT;
            goto err2;
        }

        refinop->ino = ino;
        refinop->nlink = unpack_u32(db_obj_stat, &s, st_nlink);
        refinop->refcnt = nref;
        refinop->nlookup = nlookup;
        refinop->nodelete = 0;

        ret = avl_tree_insert(ref_inodes->ref_inodes, &refinop);
        if (ret != 0)
            goto err2;
    }

    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);

    *inop = refinop;
    return 0;

err2:
    free(refinop);
err1:
    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);
    return ret;
}

static int
dec_refcnt(struct ref_inodes *ref_inodes, int32_t nlink, int32_t nref,
           int32_t nlookup, struct ref_ino *inop)
{
    int err = 0;

    pthread_mutex_lock(&ref_inodes->ref_inodes_mtx);

    adj_refcnt(&inop->nlink, -nlink);
    adj_refcnt(&inop->refcnt, -nref);
    adj_refcnt(&inop->nlookup, -nlookup);

    if (!inop->nodelete && inop->nlink == 0 && inop->refcnt == 0
        && inop->nlookup == 0) {
        err = avl_tree_delete(ref_inodes->ref_inodes, &inop);
        if (!err)
            free(inop);
    }

    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);

    return err;
}

static int
set_ref_inode_nodelete(struct back_end *be, inum_t root_id,
                       struct ref_inodes *ref_inodes, inum_t ino, int nodelete)
{
    int ret;
    struct ref_ino refino, *refinop;
    uint64_t nlink, refcnt, nlookup;

    pthread_mutex_lock(&ref_inodes->ref_inodes_mtx);

    refino.ino = ino;
    refinop = &refino;

    ret = avl_tree_search(ref_inodes->ref_inodes, &refinop, &refinop);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err;
    }

    refinop->nodelete = nodelete;

    nlink = refinop->nlink;
    refcnt = refinop->refcnt;
    nlookup = refinop->nlookup;

    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);

    if (!nodelete && nlink == 0 && refcnt == 0 && nlookup == 0)
        return delete_file(be, root_id, ino);

    return 0;

err:
    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);
    return ret;
}

static int
remove_ulinked_nodes(struct back_end *be, inum_t root_id)
{
    int ret;
    struct back_end_iter *iter;

    for (;;) {
        struct db_key k;
        struct space_alloc_ctx sctx;
        uint64_t k_ino;

        ret = back_end_iter_new(&iter, be);
        if (ret != 0)
            return ret;

        pack_u32(db_key, &k, type, TYPE_ULINKED_INODE);
        pack_u64(db_key, &k, ino, 0);

        ret = back_end_iter_search(iter, &k);
        if (ret < 0) {
            back_end_iter_free(iter);
            if (ret != -EADDRNOTAVAIL)
                return ret;
            break;
        }

        ret = back_end_iter_get(iter, &k, NULL, NULL);
        back_end_iter_free(iter);
        if (ret != 0) {
            if (ret != -EADDRNOTAVAIL)
                return ret;
            break;
        }

        if (unpack_u32(db_key, &k, type) != TYPE_ULINKED_INODE)
            break;

        ret = back_end_trans_new(be);
        if (ret != 0)
            return ret;

        ret = space_alloc_init_op(&sctx, be);
        if (ret != 0)
            goto err1;

        k_ino = unpack_u64(db_key, &k, ino);

        infomsgf("Warning: Removing I-node %" PRIu64 " with no links\n", k_ino);

        ret = delete_file(be, root_id, k_ino);
        if (ret != 0)
            goto err2;

        ret = space_alloc_finish_op(&sctx, be);
        if (ret != 0)
            goto err1;

        ret = back_end_trans_commit(be);
        if (ret != 0)
            goto err1;
    }

    return 0;

err2:
    space_alloc_abort_op(be);
err1:
    back_end_trans_abort(be);
    return ret;
}

static void
do_set_ts(struct disk_timespec *ts, struct utim *srcts)
{
    struct utim timespec;

    if (srcts == NULL) {
        struct timespec tmp;

        if (clock_gettime(CLOCK_REALTIME, &tmp) != 0) {
            omemset(ts, 0);
            return;
        }
        timespec.sec = tmp.tv_sec;
        timespec.nsec = tmp.tv_nsec;
        srcts = &timespec;
    }

    pack_i32(disk_timespec, ts, tv_sec, srcts->sec);
    pack_i32(disk_timespec, ts, tv_nsec, srcts->nsec);
}

static void
set_ts(struct disk_timespec *atim, struct disk_timespec *mtim,
       struct disk_timespec *ctim)
{
    if (atim != NULL)
        do_set_ts(atim, NULL);
    if (mtim != NULL)
        do_set_ts(mtim, NULL);
    if (ctim != NULL)
        do_set_ts(ctim, NULL);
}

static void
deserialize_ts(struct utim *ts, struct disk_timespec *disk_ts)
{
    ts->sec = unpack_i32(disk_timespec, disk_ts, tv_sec);
    ts->nsec = unpack_i32(disk_timespec, disk_ts, tv_nsec);
}

#define set_times(s, ds, which) \
    do { \
        struct utim ts; \
        \
        deserialize_ts(&ts, packed_st_tim(ds, which)); \
        set_time_sec(s, which, ts.sec); \
        set_time_nsec(s, which, ts.nsec); \
    } while (0)

static void
deserialize_stat(struct stat *s, struct db_obj_stat *ds)
{
    s->st_dev = unpack_u64(db_obj_stat, ds, st_dev);
    s->st_ino = unpack_u64(db_obj_stat, ds, st_ino);
    s->st_mode = unpack_u32(db_obj_stat, ds, st_mode);
    s->st_nlink = unpack_u32(db_obj_stat, ds, st_nlink);
    s->st_uid = unpack_u32(db_obj_stat, ds, st_uid);
    s->st_gid = unpack_u32(db_obj_stat, ds, st_gid);
    s->st_rdev = unpack_u64(db_obj_stat, ds, st_rdev);
    s->st_size = unpack_i64(db_obj_stat, ds, st_size);
    s->st_blksize = unpack_i64(db_obj_stat, ds, st_blksize);
    s->st_blocks = unpack_i64(db_obj_stat, ds, st_blocks);
    set_times(s, ds, a);
    set_times(s, ds, m);
    set_times(s, ds, c);
}

#undef set_times

static int
add_xattr_name(char **names, size_t *len, size_t *size, const char *name)
{
    size_t namelen = strlen(name) + 1;
    size_t newlen;

    trap
        return -EOVERFLOW;
    in
        newlen = addouzuz(*len, namelen);

    if (newlen > *size) {
        char *tmp;
        size_t newsize;

        trap
            return -EOVERFLOW;
        in
            newsize = mulouzuz(newlen, 2);

        tmp = do_realloc(*names, newsize);
        if (tmp == NULL)
            return MINUS_ERRNO;
        *names = tmp;
        *size = newsize;
    }

    memcpy(*names + *len, name, namelen);
    *len += namelen;

    return 0;
}

/*
 * This function must be called under a transaction to allow cancelling changes
 * in case of an error.
 */
static int
truncate_file(struct back_end *be, inum_t ino, off_t oldsize, off_t newsize,
              uint64_t *delpg)
{
    int ret;
    size_t lastpgsz;
    struct db_key k;
    uint64_t i;
    uint64_t newnumpg, oldnumpg;
    uint64_t numdelpg = 0;

    ASSERT_UNDER_TRANS(be);

    if (newsize >= oldsize)
        goto end;

    trap
        oldnumpg = OFF_MAX / PG_SIZE + 1;
    in
        oldnumpg = (addos64s64(oldsize, PG_SIZE) - 1) / PG_SIZE;
    trap
        newnumpg = OFF_MAX / PG_SIZE + 1;
    in
        newnumpg = (addos64s64(newsize, PG_SIZE) - 1) / PG_SIZE;

    pack_u32(db_key, &k, type, TYPE_PAGE);
    pack_u64(db_key, &k, ino, ino);

    for (i = oldnumpg - 1; i > newnumpg; i--) {
        /* FIXME: use iterator to improve efficiency */

        pack_u64(db_key, &k, pgno, i);

        ret = back_end_delete(be, &k);
        if (ret == 0)
            ++numdelpg;
        else if (ret != -EADDRNOTAVAIL) /* file may be sparse */
            return ret;
    }

    if (oldnumpg > newnumpg) {
        pack_u64(db_key, &k, pgno, newnumpg);

        ret = back_end_delete(be, &k);
        if (ret == 0)
            ++numdelpg;
        else if (ret != -EADDRNOTAVAIL)
            return ret;
    }

    lastpgsz = newsize % PG_SIZE;
    if (lastpgsz > 0) {
        char buf[PG_SIZE];

        pack_u64(db_key, &k, pgno, newnumpg - 1);

        ret = back_end_look_up(be, &k, NULL, buf, NULL, 0);
        if (ret != 1)
            return ret == 0 ? -ENOENT : ret;

        memset(buf + lastpgsz, 0, sizeof(buf) - lastpgsz);

        return back_end_replace(be, &k, buf, sizeof(buf));
    }

end:
    *delpg = numdelpg;
    return 0;
}

/*
 * This function must be called under a transaction to allow cancelling changes
 * in case of an error.
 */
static int
delete_file(struct back_end *be, inum_t root_id, inum_t ino)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    uint32_t s_st_mode;

    ASSERT_UNDER_TRANS(be);

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, ino);

    ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    s_st_mode = unpack_u32(db_obj_stat, &s, st_mode);

    if (S_ISREG(s_st_mode) || S_ISLNK(s_st_mode)) {
        off_t size;
        uint64_t i, numpg;

        size = unpack_i64(db_obj_stat, &s, st_size);
        if (S_ISLNK(s_st_mode)) /* size does not include null terminator */
            ++size;

        trap
            numpg = OFF_MAX / PG_SIZE + 1;
        in
            numpg = (addos64s64(size, PG_SIZE) - 1) / PG_SIZE;

        pack_u32(db_key, &k, type, TYPE_PAGE);

        i = numpg;
        while (i > 0) {
            --i;
            pack_u64(db_key, &k, pgno, i);

            ret = back_end_delete(be, &k);
            if (ret != 0 && ret != -EADDRNOTAVAIL) /* file may be sparse */
                return ret;
        }
    }

    pack_u32(db_key, &k, type, TYPE_STAT);

    ret = back_end_delete(be, &k);
    if (ret != 0)
        return ret;

    pack_u32(db_key, &k, type, TYPE_ULINKED_INODE);

    ret = back_end_delete(be, &k);
    if (ret != 0)
        return ret;

    return release_ino(be, root_id, ino);
}

static void
free_iov(struct iovec *iov, int count)
{
    int i;

    for (i = 0; i < count; i++)
        free(iov[i].iov_base);

    free(iov);
}

/*
 * Side effects:
 * - Sets link count of new node to 1
 * - Sets lookup count of new node to 1
 */
static int
new_node(struct back_end *be, struct ref_inodes *ref_inodes, inum_t parent,
         const char *name, uid_t uid, gid_t gid, mode_t mode, dev_t rdev,
         off_t size, struct stat *attr, struct ref_ino **inop, int notrans)
{
    int ret;
    inum_t ino;
    struct db_key k;
    struct db_obj_stat ps, s;
    struct ref_ino *refinop[2];

    if ((mode & S_IFMT) == S_IFDIR)
        return -EINVAL;

    if (!notrans) {
        ret = back_end_trans_new(be);
        if (ret != 0)
            return ret;
    }

    ret = get_ino(be, &ino);
    if (ret != 0)
        goto err1;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, ino);

    pack_u64(db_obj_stat, &s, st_dev, 64 * 1024);
    pack_u64(db_obj_stat, &s, st_ino, ino);
    pack_u32(db_obj_stat, &s, st_mode, mode & (S_IFMT | ALL_PERMS));
    pack_u32(db_obj_stat, &s, st_nlink, 0);
    pack_u32(db_obj_stat, &s, st_uid, uid);
    pack_u32(db_obj_stat, &s, st_gid, gid);
    pack_u64(db_obj_stat, &s, st_rdev, rdev);
    pack_i64(db_obj_stat, &s, st_size, size);
    pack_i64(db_obj_stat, &s, st_blksize, PG_SIZE);
    pack_i64(db_obj_stat, &s, st_blocks, 0);
    set_ts(packed_st_tim(&s, a), packed_st_tim(&s, m), packed_st_tim(&s, c));
    pack_u32(db_obj_stat, &s, num_ents, 0);

    ret = back_end_insert(be, &k, &s, sizeof(s));
    if (ret != 0)
        goto err1;

    ret = new_node_link(be, ref_inodes, ino, parent, name, &refinop[0]);
    if (ret != 0)
        goto err1;

    ret = inc_refcnt(be, ref_inodes, ino, 0, 0, 1, &refinop[1]);
    if (ret != 0)
        goto err2;

    pack_u64(db_key, &k, ino, parent);

    ret = back_end_look_up(be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err3;
    }

    pack_u32(db_obj_stat, &ps, num_ents,
             unpack_u32(db_obj_stat, &ps, num_ents) + 1);

    assert(unpack_u64(db_obj_stat, &ps, st_ino) == unpack_u64(db_key, &k, ino));
    ret = back_end_replace(be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err3;

    if (!notrans) {
        ret = back_end_trans_commit(be);
        if (ret != 0)
            goto err3;
    }

    if (attr != NULL) {
        deserialize_stat(attr, &s);
        attr->st_nlink = 1;
    }
    omemcpy_array(inop, refinop, 2);

    return 0;

err3:
    dec_refcnt(ref_inodes, 0, 0, -1, refinop[1]);
err2:
    dec_refcnt(ref_inodes, -1, 0, 0, refinop[0]);
err1:
    if (!notrans)
        back_end_trans_abort(be);
    return ret;
}

/*
 * Side effects:
 * - Increments link count of target node
 *
 * This function should be called under a transaction to allow cancelling
 * changes in case of an error.
 */
static int
new_node_link(struct back_end *be, struct ref_inodes *ref_inodes, inum_t ino,
              inum_t newparent, const char *newname, struct ref_ino **inop)
{
    int ret;
    struct db_key k;
    struct db_obj_dirent de;
    struct db_obj_stat s;
    struct ref_ino *refinop;

    ASSERT_UNDER_TRANS(be);

    pack_u32(db_key, &k, type, TYPE_DIRENT);
    pack_u64(db_key, &k, ino, newparent);
    _strlcpy(packed_memb_addr(db_key, &k, name), newname,
             packed_memb_size(db_key, name));

    pack_u64(db_obj_dirent, &de, ino, ino);

    ret = back_end_insert(be, &k, &de, sizeof(de));
    if (ret != 0)
        return ret;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, ino);

    ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    pack_u32(db_obj_stat, &s, st_nlink,
             unpack_u32(db_obj_stat, &s, st_nlink) + 1);

    assert(unpack_u64(db_obj_stat, &s, st_ino) == unpack_u64(db_key, &k, ino));
    ret = back_end_replace(be, &k, &s, sizeof(s));
    if (ret != 0)
        return ret;

    ret = inc_refcnt(be, ref_inodes, ino, 1, 0, 0, &refinop);
    if (ret != 0)
        return ret;

    *inop = refinop;
    return 0;
}

/*
 * Side effects:
 * - Sets link count of new directory to 2
 * - Increments link count of parent directory
 * - Sets lookup count of new directory to 1
 */
static int
new_dir(struct back_end *be, inum_t root_id, struct ref_inodes *ref_inodes,
        inum_t parent, const char *name, uid_t uid, gid_t gid, mode_t mode,
        struct stat *attr, struct ref_ino **inop, int notrans)
{
    int ret;
    int rootdir = parent == 0;
    inum_t ino;
    struct db_key k;
    struct db_obj_stat s;
    struct ref_ino *refinop[4];

    if (!notrans) {
        ret = back_end_trans_new(be);
        if (ret != 0)
            return ret;
    }

    if (rootdir)
        parent = ino = root_id;
    else {
        ret = get_ino(be, &ino);
        if (ret != 0)
            goto err1;
    }

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, ino);

    pack_u64(db_obj_stat, &s, st_dev, 64 * 1024);
    pack_u64(db_obj_stat, &s, st_ino, ino);
    pack_u32(db_obj_stat, &s, st_mode, S_IFDIR | (mode & ALL_PERMS));
    pack_u32(db_obj_stat, &s, st_nlink, 0);
    pack_u32(db_obj_stat, &s, st_uid, uid);
    pack_u32(db_obj_stat, &s, st_gid, gid);
    pack_u64(db_obj_stat, &s, st_rdev, 0);
    pack_i64(db_obj_stat, &s, st_size, 0);
    pack_i64(db_obj_stat, &s, st_blksize, PG_SIZE);
    pack_i64(db_obj_stat, &s, st_blocks, 0);
    set_ts(packed_st_tim(&s, a), packed_st_tim(&s, m), packed_st_tim(&s, c));
    pack_u32(db_obj_stat, &s, num_ents, 0);

    ret = back_end_insert(be, &k, &s, sizeof(s));
    if (ret != 0)
        goto err1;

    ret = new_dir_link(be, ref_inodes, ino, ino, NAME_CUR_DIR, &refinop[0]);
    if (ret != 0)
        goto err1;
    ret = new_dir_link(be, ref_inodes, parent, ino, NAME_PARENT_DIR,
                       &refinop[1]);
    if (ret != 0)
        goto err2;

    if (!rootdir) {
        ret = new_dir_link(be, ref_inodes, ino, parent, name, &refinop[2]);
        if (ret != 0)
            goto err3;
    }

    ret = inc_refcnt(be, ref_inodes, ino, 0, 0, 1, &refinop[3]);
    if (ret != 0)
        goto err4;

    if (!rootdir) {
        struct db_obj_stat ps;

        pack_u64(db_key, &k, ino, parent);

        ret = back_end_look_up(be, &k, NULL, &ps, NULL, 0);
        if (ret != 1) {
            if (ret == 0)
                ret = -ENOENT;
            goto err5;
        }

        pack_u32(db_obj_stat, &ps, num_ents,
                 unpack_u32(db_obj_stat, &ps, num_ents) + 1);

        assert(unpack_u64(db_obj_stat, &ps, st_ino)
               == unpack_u64(db_key, &k, ino));
        ret = back_end_replace(be, &k, &ps, sizeof(ps));
        if (ret != 0)
            goto err5;
    }

    if (!notrans) {
        ret = back_end_trans_commit(be);
        if (ret != 0)
            goto err5;
    }

    if (attr != NULL) {
        deserialize_stat(attr, &s);
        attr->st_nlink = 2;
    }
    omemcpy_array(inop, refinop, 4);

    return 0;

err5:
    dec_refcnt(ref_inodes, 0, 0, -1, refinop[3]);
err4:
    if (!rootdir)
        dec_refcnt(ref_inodes, -1, 0, 0, refinop[2]);
err3:
    dec_refcnt(ref_inodes, -1, 0, 0, refinop[1]);
err2:
    dec_refcnt(ref_inodes, -1, 0, 0, refinop[0]);
err1:
    if (!notrans)
        back_end_trans_abort(be);
    return ret;
}

/*
 * Side effects:
 * - Decreases link count of target directory by 2 (to 0)
 * - Decrements link count of parent directory
 */
static int
rem_dir(struct back_end *be, inum_t root_id, struct ref_inodes *ref_inodes,
        inum_t ino, inum_t parent, const char *name, int notrans, int nodelete)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct ref_ino *refinop[3];

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, ino);
    ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;
    if (unpack_u32(db_obj_stat, &s, num_ents) != 0)
        return -ENOTEMPTY;

    pack_u64(db_key, &k, ino, parent);
    ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    if (!nodelete) {
        ret = set_ref_inode_nodelete(be, root_id, ref_inodes, ino, 1);
        if (ret != 0)
            return ret;
    }

    if (notrans)
        ASSERT_UNDER_TRANS(be);
    else {
        ret = back_end_trans_new(be);
        if (ret != 0)
            goto err1;
    }

    ret = rem_dir_link(be, root_id, ref_inodes, ino, parent, name, &refinop[0]);
    if (ret != 0)
        goto err2;

    ret = rem_dir_link(be, root_id, ref_inodes, parent, ino, NAME_PARENT_DIR,
                       &refinop[1]);
    if (ret != 0)
        goto err3;
    ret = rem_dir_link(be, root_id, ref_inodes, ino, ino, NAME_CUR_DIR,
                       &refinop[2]);
    if (ret != 0)
        goto err4;

    pack_u32(db_obj_stat, &s, num_ents,
             unpack_u32(db_obj_stat, &s, num_ents) - 1);
    ret = back_end_replace(be, &k, &s, sizeof(s));
    if (ret != 0)
        goto err5;

    if (!notrans) {
        ret = back_end_trans_commit(be);
        if (ret != 0)
            goto err5;
    }

    if (!nodelete)
        set_ref_inode_nodelete(be, root_id, ref_inodes, ino, 0);

    return 0;

err5:
    inc_refcnt(be, ref_inodes, ino, 1, 0, 0, &refinop[2]);
err4:
    inc_refcnt(be, ref_inodes, parent, 1, 0, 0, &refinop[1]);
err3:
    inc_refcnt(be, ref_inodes, ino, 1, 0, 0, &refinop[0]);
err2:
    if (!notrans)
        back_end_trans_abort(be);
err1:
    if (!nodelete)
        set_ref_inode_nodelete(be, root_id, ref_inodes, ino, 0);
    return ret;
}

/*
 * Side effects:
 * - Increments link count of target directory
 *
 * This function must be called under a transaction to allow cancelling changes
 * in case of an error.
 */
static int
new_dir_link(struct back_end *be, struct ref_inodes *ref_inodes, inum_t ino,
             inum_t newparent, const char *newname, struct ref_ino **inop)
{
    int ret;
    struct db_key k;
    struct db_obj_dirent de;
    struct db_obj_stat s;
    struct ref_ino *refinop;

    ASSERT_UNDER_TRANS(be);

    pack_u32(db_key, &k, type, TYPE_DIRENT);
    pack_u64(db_key, &k, ino, newparent);
    _strlcpy(packed_memb_addr(db_key, &k, name), newname,
             packed_memb_size(db_key, name));

    pack_u64(db_obj_dirent, &de, ino, ino);

    ret = back_end_insert(be, &k, &de, sizeof(de));
    if (ret != 0)
        return ret;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, ino);

    ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    pack_u32(db_obj_stat, &s, st_nlink,
             unpack_u32(db_obj_stat, &s, st_nlink) + 1);

    assert(unpack_u64(db_obj_stat, &s, st_ino) == unpack_u64(db_key, &k, ino));
    ret = back_end_replace(be, &k, &s, sizeof(s));
    if (ret != 0)
        return ret;

    ret = inc_refcnt(be, ref_inodes, ino, 1, 0, 0, &refinop);
    if (ret != 0)
        return ret;

    *inop = refinop;
    return 0;
}

/*
 * Side effects:
 * - Decrements link count of target node and deletes if unreferenced
 *
 * This function must be called under a transaction to allow cancelling changes
 * in case of an error.
 */
static int
rem_node_link(struct back_end *be, inum_t root_id,
              struct ref_inodes *ref_inodes, inum_t ino, inum_t parent,
              const char *name, int *deleted, struct ref_ino **inop)
{
    int ret;
    struct db_key k;
    struct ref_ino refino, *refinop;

    ASSERT_UNDER_TRANS(be);

    pack_u32(db_key, &k, type, TYPE_DIRENT);
    pack_u64(db_key, &k, ino, parent);
    _strlcpy(packed_memb_addr(db_key, &k, name), name,
             packed_memb_size(db_key, name));

    ret = back_end_delete(be, &k);
    if (ret != 0)
        return ret;

    refino.ino = ino;
    refinop = &refino;

    pthread_mutex_lock(&ref_inodes->ref_inodes_mtx);
    ret = avl_tree_search(ref_inodes->ref_inodes, &refinop, &refinop);
    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    ret = unref_inode(be, root_id, ref_inodes, refinop, -1, 0, 0, deleted);
    if (ret == 0)
        *inop = refinop;

    return ret;
}

/*
 * Side effects:
 * - Decrements link count of target directory and deletes if unreferenced
 *
 * This function must be called under a transaction to allow cancelling changes
 * in case of an error.
 */
static int
rem_dir_link(struct back_end *be, inum_t root_id, struct ref_inodes *ref_inodes,
             inum_t ino, inum_t parent, const char *name, struct ref_ino **inop)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct ref_ino refino, *refinop;

    ASSERT_UNDER_TRANS(be);

    pack_u32(db_key, &k, type, TYPE_DIRENT);
    pack_u64(db_key, &k, ino, parent);
    _strlcpy(packed_memb_addr(db_key, &k, name), name,
             packed_memb_size(db_key, name));

    ret = back_end_delete(be, &k);
    if (ret != 0)
        return ret;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, ino);

    ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    refino.ino = ino;
    refinop = &refino;

    pthread_mutex_lock(&ref_inodes->ref_inodes_mtx);
    ret = avl_tree_search(ref_inodes->ref_inodes, &refinop, &refinop);
    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    ret = unref_inode(be, root_id, ref_inodes, refinop, -1, 0, 0, NULL);
    if (ret == 0)
        *inop = refinop;

    return ret;
}

static void
space_alloc_cb(uint64_t sz, int dealloc, void *ctx)
{
    struct space_alloc_ctx *actx = ctx;

    if (dealloc)
        actx->delta -= sz;
    else
        actx->delta += sz;
}

static int
space_alloc_set_hook(struct back_end *be, void (*cb)(uint64_t, int, void *),
                     void *cbctx)
{
    struct db_alloc_cb alloc_cb = {
        .alloc_cb       = cb,
        .alloc_cb_ctx   = cbctx
    };

    return back_end_ctl(be, BACK_END_DBM_OP_SET_ALLOC_HOOK, &alloc_cb);
}

static int
space_alloc_init_op(struct space_alloc_ctx *ctx, struct back_end *be)
{
    int err;

    err = space_alloc_set_hook(be, &space_alloc_cb, ctx);
    if (!err)
        ctx->delta = 0;

    return err;
}

static int
space_alloc_abort_op(struct back_end *be)
{
    return space_alloc_set_hook(be, NULL, NULL);
}

static int
space_alloc_finish_op(struct space_alloc_ctx *ctx, struct back_end *be)
{
    int ret;
    struct db_key k;
    struct db_obj_header hdr;

    ret = space_alloc_set_hook(be, NULL, NULL);
    if (ret != 0 || ctx->delta == 0)
        return ret;

    /* FIXME: later, assert that the remaining code in this function never
       results in any nonzero overall space allocation delta, to guarantee
       accuracy of the usedbytes field */

    pack_u32(db_key, &k, type, TYPE_HEADER);

    ret = back_end_look_up(be, &k, NULL, &hdr, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -EILSEQ : ret;

    pack_u64(db_obj_header, &hdr, usedbytes,
             unpack_u64(db_obj_header, &hdr, usedbytes) + ctx->delta);

    return back_end_replace(be, &k, &hdr, sizeof(hdr));
}

static int
do_look_up(void *args)
{
    int ret;
    struct db_key k;
    struct db_obj_dirent de;
    struct op_args *opargs = args;

    switch (unpack_u32(db_key, &opargs->k, type)) {
    case TYPE_DIRENT:
        ret = back_end_look_up(opargs->be, &opargs->k, NULL, &de, NULL, 0);
        if (ret != 1)
            return ret;

        pack_u32(db_key, &k, type, TYPE_STAT);
        pack_u64(db_key, &k, ino, unpack_u64(db_obj_dirent, &de, ino));
        ret = back_end_look_up(opargs->be, &k, NULL, &opargs->s, NULL, 0);
        if (ret != 1)
            return ret;

        break;
    case TYPE_STAT:
        ret = back_end_look_up(opargs->be, &opargs->k, NULL, &opargs->s, NULL,
                               0);
        if (ret != 1)
            return ret;

        break;
    default:
        return -EIO;
    }

    if (opargs->op_data.inc_lookup_cnt) {
        ret = inc_refcnt(opargs->be, opargs->ref_inodes,
                         unpack_u64(db_obj_stat, &opargs->s, st_ino), 0, 0, 1,
                         opargs->refinop);
        if (ret != 0)
            return ret;
    }

    return 1;
}

static int
do_setattr(void *args)
{
    int ret;
    int to_set, trunc;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = args;
    struct space_alloc_ctx sctx;
    struct utim tm;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, opargs->ino);

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    to_set = opargs->op_data.to_set;
    trunc = !!(to_set & REQUEST_SET_ATTR_SIZE);

    if (trunc) {
        uint64_t numdelpg;

        if (!S_ISREG(unpack_u32(db_obj_stat, &s, st_mode)))
            return -EINVAL;

        ret = back_end_trans_new(opargs->be);
        if (ret != 0)
            return ret;

        ret = space_alloc_init_op(&sctx, opargs->be);
        if (ret != 0)
            goto err1;

        ret = truncate_file(opargs->be, opargs->ino,
                            unpack_i64(db_obj_stat, &s, st_size),
                            opargs->attr.st_size, &numdelpg);
        if (ret != 0)
            goto err2;
        pack_i64(db_obj_stat, &s, st_size, opargs->attr.st_size);
        pack_i64(db_obj_stat, &s, st_blocks,
                 unpack_i64(db_obj_stat, &s, st_blocks)
                 - numdelpg * BLOCKS_PER_PG);
    }

    if (to_set & REQUEST_SET_ATTR_MODE) {
        pack_u32(db_obj_stat, &s, st_mode,
                 (unpack_u32(db_obj_stat, &s, st_mode) & ~ALL_PERMS)
                 | (opargs->attr.st_mode & ALL_PERMS));
    }

    if (to_set & REQUEST_SET_ATTR_UID)
        pack_u32(db_obj_stat, &s, st_uid, opargs->attr.st_uid);
    if (to_set & REQUEST_SET_ATTR_GID)
        pack_u32(db_obj_stat, &s, st_gid, opargs->attr.st_gid);

    if ((to_set & (REQUEST_SET_ATTR_MTIME_NOW | REQUEST_SET_ATTR_MTIME)) == 0) {
        /* POSIX-1.2008, ftruncate, para. 3:
         * Upon successful completion, if fildes refers to a regular file,
         * ftruncate() shall mark for update the last data modification and last
         * file status change timestamps of the file.
         *
         * ", open, para. 8:
         * If O_TRUNC is set and the file did previously exist, upon successful
         * completion, open() shall mark for update the last data modification
         * and last file status change timestamps of the file. */
        if (trunc)
            do_set_ts(packed_st_tim(&s, m), NULL);
    } else {
        if (to_set & REQUEST_SET_ATTR_MTIME_NOW)
            do_set_ts(packed_st_tim(&s, m), NULL);
        if (to_set & REQUEST_SET_ATTR_MTIME) {
            tm.sec = opargs->attr.st_mtime;
            tm.nsec = st_mtime_nsec(&opargs->attr);
            do_set_ts(packed_st_tim(&s, m), &tm);
        }
    }

    if (to_set & REQUEST_SET_ATTR_ATIME_NOW)
        do_set_ts(packed_st_tim(&s, a), NULL);
    if (to_set & REQUEST_SET_ATTR_ATIME) {
        tm.sec = opargs->attr.st_atime;
        tm.nsec = st_atime_nsec(&opargs->attr);
        do_set_ts(packed_st_tim(&s, a), &tm);
    }

    /* ", ftruncate, para. 3:
     * "
     *
     * ", open, para. 8:
     * "
     *
     * ", chmod, para. 5:
     * Upon successful completion, chmod() shall mark for update the last file
     * status change timestamp of the file.
     *
     * ", chown, para. 6:
     * Upon successful completion, chown() shall mark for update the last file
     * status change timestamp of the file.
     *
     * ", futimens, para. 8:
     * Upon completion, futimens() and utimensat() shall mark the last file
     * status change timestamp for update. */
    do_set_ts(packed_st_tim(&s, c), NULL);

    ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
    if (ret != 0) {
        if (trunc)
            goto err2;
        return ret;
    }

    if (trunc) {
        ret = space_alloc_finish_op(&sctx, opargs->be);
        if (ret != 0)
            goto err1;

        ret = back_end_trans_commit(opargs->be);
        if (ret != 0)
            goto err1;
    }

    deserialize_stat(&opargs->attr, &s);
    if (S_ISDIR(opargs->attr.st_mode))
        opargs->attr.st_size = unpack_u32(db_obj_stat, &s, num_ents);

    return 0;

err2:
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_read_symlink(void *args)
{
    char *link;
    int ret;
    size_t buflen;
    struct db_key k;
    struct op_args *opargs = args;

    pack_u32(db_key, &k, type, TYPE_PAGE);
    pack_u64(db_key, &k, ino, opargs->ino);
    pack_u64(db_key, &k, pgno, 0);

    ret = back_end_look_up(opargs->be, &k, NULL, NULL, &buflen, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    link = do_malloc(buflen);
    if (link == NULL)
        return MINUS_ERRNO;

    ret = back_end_look_up(opargs->be, &k, NULL, link, NULL, 0);
    if (ret != 1) {
        free(link);
        return ret == 0 ? -ENOENT : ret;
    }

    opargs->op_data.rdwr_data.a_rd = link;

    return 0;
}

static int
do_forget(void *args)
{
    int ret;
    struct op_args *opargs = args;
    struct ref_ino refino, *refinop;
    struct space_alloc_ctx sctx;
    uint64_t to_unref, unref;

    if (!opargs->ro) {
        ret = back_end_trans_new(opargs->be);
        if (ret != 0)
            return ret;

        ret = space_alloc_init_op(&sctx, opargs->be);
        if (ret != 0)
            goto err1;
    }

    refino.ino = opargs->ino;
    refinop = &refino;

    pthread_mutex_lock(&opargs->ref_inodes->ref_inodes_mtx);
    ret = avl_tree_search(opargs->ref_inodes->ref_inodes, &refinop, &refinop);
    pthread_mutex_unlock(&opargs->ref_inodes->ref_inodes_mtx);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err2;
    }

    for (to_unref = opargs->op_data.nlookup; to_unref > 0; to_unref -= unref) {
        unref = MIN(UNREF_MAX, to_unref);

        ret = unref_inode(opargs->be, opargs->root_id, opargs->ref_inodes,
                          refinop, 0, 0, -(int32_t)unref, NULL);
        if (ret != 0)
            goto err2;
    }

    if (!opargs->ro) {
        ret = space_alloc_finish_op(&sctx, opargs->be);
        if (ret != 0)
            goto err1;

        ret = back_end_trans_commit(opargs->be);
        if (ret != 0)
            goto err1;
    }

    pthread_mutex_lock(&opargs->ref_inodes->ref_inodes_mtx);
    if (!refinop->nodelete && refinop->nlink == 0 && refinop->refcnt == 0
        && refinop->nlookup == 0) {
        if (avl_tree_delete(opargs->ref_inodes->ref_inodes, &refinop) == 0)
            free(refinop);
    }
    pthread_mutex_unlock(&opargs->ref_inodes->ref_inodes_mtx);

    return 0;

err2:
    if (opargs->ro)
        return ret;
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_create_node(void *args)
{
    const struct ctx *ctx;
    int mode;
    int ret;
    struct db_key k;
    struct db_obj_stat ps;
    struct op_args *opargs = args;
    struct space_alloc_ctx sctx;

    ctx = opargs->ctx;

    mode = opargs->op_data.mknod_data.mode;

    if ((mode & S_IFMT) == S_IFDIR || (mode & S_IFMT) == S_IFLNK)
        return -EINVAL;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = space_alloc_init_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    /* POSIX-1.2008, mknod, para. 7:
     * Upon successful completion, mknod() shall mark for update the last data
     * access, last data modification, and last file status change timestamps of
     * the file.
     *
     * ", mkfifo, para. 5:
     * Upon successful completion, mkfifo() shall mark for update the last data
     * access, last data modification, and last file status change timestamps of
     * the file. */
    ret = new_node(opargs->be, opargs->ref_inodes, opargs->ino,
                   opargs->op_data.mknod_data.name, ctx->uid, ctx->gid,
                   mode & ~ctx->umask, opargs->op_data.mknod_data.rdev, 0,
                   &opargs->attr, opargs->refinop, 1);
    if (ret != 0)
        goto err2;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, opargs->ino);

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err3;
    }

    /* ", mknod, para. 7:
     * Also, the last data modification and last file status change timestamps
     * of the directory that contains the new entry shall be marked for
     * update.
     *
     * ", mkfifo, para. 5:
     * Also, the last data modification and last file status change timestamps
     * of the directory that contains the new entry shall be marked for
     * update. */
    set_ts(NULL, packed_st_tim(&ps, m), packed_st_tim(&ps, c));

    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err3;

    ret = space_alloc_finish_op(&sctx, opargs->be);
    if (ret != 0)
        goto err3;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err3;

    dump_db(opargs->be);

    return 0;

err3:
    dec_refcnt(opargs->ref_inodes, 0, 0, -1, opargs->refinop[1]);
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, opargs->refinop[0]);
err2:
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_create_dir(void *args)
{
    const struct ctx *ctx;
    int ret;
    int rootdir;
    struct db_key k;
    struct db_obj_stat ps;
    struct op_args *opargs = args;
    struct space_alloc_ctx sctx;

    ctx = opargs->ctx;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = space_alloc_init_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    /* POSIX-1.2008, mkdir, para. 6:
     * Upon successful completion, mkdir() shall mark for update the last data
     * access, last data modification, and last file status change timestamps of
     * the directory. */
    ret = new_dir(opargs->be, opargs->root_id, opargs->ref_inodes, opargs->ino,
                  opargs->op_data.mknod_data.name, ctx->uid, ctx->gid,
                  opargs->op_data.mknod_data.mode & ~ctx->umask, &opargs->attr,
                  opargs->refinop, 1);
    if (ret != 0)
        goto err2;

    rootdir = opargs->ino == 0;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, opargs->ino);

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err3;
    }

    /* ", mkdir, para. 6:
     * Also, the last data modification and last file status change timestamps
     * of the directory that contains the new entry shall be marked for
     * update. */
    set_ts(NULL, packed_st_tim(&ps, m), packed_st_tim(&ps, c));

    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err3;

    ret = space_alloc_finish_op(&sctx, opargs->be);
    if (ret != 0)
        goto err3;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err3;

    dump_db(opargs->be);

    return 0;

err3:
    dec_refcnt(opargs->ref_inodes, 0, 0, -1, opargs->refinop[3]);
    if (!rootdir)
        dec_refcnt(opargs->ref_inodes, -1, 0, 0, opargs->refinop[2]);
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, opargs->refinop[1]);
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, opargs->refinop[0]);
err2:
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_remove_node_link(void *args)
{
    const char *name;
    int deleted;
    int ret;
    inum_t parent;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = args;
    struct ref_ino *refinop;
    struct space_alloc_ctx sctx;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = space_alloc_init_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    parent = opargs->op_data.link_data.parent;
    name = opargs->op_data.link_data.name;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, parent);

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err2;
    }

    ret = set_ref_inode_nodelete(opargs->be, opargs->root_id,
                                 opargs->ref_inodes, opargs->ino, 1);
    if (ret != 0)
        goto err2;

    ret = rem_node_link(opargs->be, opargs->root_id, opargs->ref_inodes,
                        opargs->ino, parent, name, &deleted, &refinop);
    if (ret != 0)
        goto err3;

    /* POSIX-1.2008, unlink, para. 4:
     * Upon successful completion, unlink() shall mark for update the last data
     * modification and last file status change timestamps of the parent
     * directory. */
    set_ts(NULL, packed_st_tim(&s, m), packed_st_tim(&s, c));
    pack_u32(db_obj_stat, &s, num_ents,
             unpack_u32(db_obj_stat, &s, num_ents) - 1);

    ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
    if (ret != 0)
        goto err4;

    pack_u64(db_key, &k, ino, opargs->ino);

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err4;
    }

    if (!deleted) {
        /* ", unlink, para. 4:
         * Also, if the file's link count is not 0, the last file status change
         * timestamp of the file shall be marked for update. */
        do_set_ts(packed_st_tim(&s, c), NULL);

        ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
        if (ret != 0)
            goto err4;
    }

    if (unpack_u32(db_obj_stat, &s, st_nlink) == 0) {
        pack_u32(db_key, &k, type, TYPE_ULINKED_INODE);

        ret = back_end_insert(opargs->be, &k, NULL, 0);
        if (ret != 0)
            goto err4;
    }

    ret = space_alloc_finish_op(&sctx, opargs->be);
    if (ret != 0)
        goto err4;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err4;

    set_ref_inode_nodelete(opargs->be, opargs->root_id, opargs->ref_inodes,
                           opargs->ino, 0);

    dump_db(opargs->be);

    return 0;

err4:
    inc_refcnt(opargs->be, opargs->ref_inodes, opargs->ino, 1, 0, 0, &refinop);
err3:
    set_ref_inode_nodelete(opargs->be, opargs->root_id, opargs->ref_inodes,
                           opargs->ino, 0);
err2:
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_remove_dir(void *args)
{
    const char *name;
    int ret;
    inum_t parent;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = args;
    struct space_alloc_ctx sctx;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, opargs->ino);

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;
    if (unpack_u32(db_obj_stat, &s, num_ents) != 0)
        return -ENOTEMPTY;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = space_alloc_init_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    parent = opargs->op_data.link_data.parent;
    name = opargs->op_data.link_data.name;

    ret = set_ref_inode_nodelete(opargs->be, opargs->root_id,
                                 opargs->ref_inodes, opargs->ino, 1);
    if (ret != 0)
        goto err2;

    ret = rem_dir(opargs->be, opargs->root_id, opargs->ref_inodes, opargs->ino,
                  parent, name, 1, 1);
    if (ret != 0)
        goto err3;

    pack_u64(db_key, &k, ino, parent);

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err4;
    }

    /* POSIX-1.2008, rmdir, para. 7:
     * Upon successful completion, rmdir() shall mark for update the last data
     * modification and last file status change timestamps of the parent
     * directory. */
    set_ts(NULL, packed_st_tim(&s, m), packed_st_tim(&s, c));

    ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
    if (ret != 0)
        goto err4;

    pack_u64(db_key, &k, ino, opargs->ino);

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err4;
    }

    if (unpack_u32(db_obj_stat, &s, st_nlink) == 0) {
        pack_u32(db_key, &k, type, TYPE_ULINKED_INODE);

        ret = back_end_insert(opargs->be, &k, NULL, 0);
        if (ret != 0)
            goto err4;
    }

    ret = space_alloc_finish_op(&sctx, opargs->be);
    if (ret != 0)
        goto err4;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err4;

    set_ref_inode_nodelete(opargs->be, opargs->root_id, opargs->ref_inodes,
                           opargs->ino, 0);

    dump_db(opargs->be);

    return 0;

err4:
    inc_refcnt(opargs->be, opargs->ref_inodes, opargs->ino, 2, 0, 0,
               opargs->refinop);
    inc_refcnt(opargs->be, opargs->ref_inodes, parent, 1, 0, 0,
               opargs->refinop);
err3:
    set_ref_inode_nodelete(opargs->be, opargs->root_id, opargs->ref_inodes,
                           opargs->ino, 0);
err2:
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_create_symlink(void *args)
{
    const char *link, *name;
    const struct ctx *ctx;
    int ret;
    inum_t parent;
    size_t len;
    struct db_key k;
    struct db_obj_stat ps;
    struct op_args *opargs = args;
    struct space_alloc_ctx sctx;

    ctx = opargs->ctx;

    parent = opargs->op_data.mknod_data.parent;
    name = opargs->op_data.mknod_data.name;
    link = opargs->op_data.mknod_data.link;

    len = strlen(link);
#if SIZE_MAX > OFF_MAX
    if (len > (size_t)OFF_MAX)
        len = OFF_MAX;
#endif

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = space_alloc_init_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    /* POSIX-1.2008, symlink, para. 7:
     * Upon successful completion, symlink() shall mark for update the last data
     * access, last data modification, and last file status change timestamps of
     * the symbolic link. */
    ret = new_node(opargs->be, opargs->ref_inodes, parent, name, ctx->uid,
                   ctx->gid, S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO, 0, len,
                   &opargs->attr, opargs->refinop, 1);
    if (ret != 0)
        goto err2;

    pack_u32(db_key, &k, type, TYPE_PAGE);
    pack_u64(db_key, &k, ino, opargs->attr.st_ino);
    pack_u64(db_key, &k, pgno, 0);

    ret = back_end_insert(opargs->be, &k, link, len + 1);
    if (ret != 0)
        goto err3;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, parent);

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err3;
    }

    /* ", symlink, para. 7:
     * Also, the last data modification and last file status change timestamps
     * of the directory that contains the new entry shall be marked for
     * update. */
    set_ts(NULL, packed_st_tim(&ps, m), packed_st_tim(&ps, c));

    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err3;

    ret = space_alloc_finish_op(&sctx, opargs->be);
    if (ret != 0)
        goto err3;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err3;

    dump_db(opargs->be);

    return 0;

err3:
    dec_refcnt(opargs->ref_inodes, 0, 0, -1, opargs->refinop[1]);
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, opargs->refinop[0]);
err2:
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_rename(void *args)
{
    const char *name, *newname;
    int existing, ret;
    inum_t parent, newparent;
    struct db_key k;
    struct db_obj_dirent dde, sde;
    struct db_obj_stat ds, ps, ss;
    struct op_args *opargs = args;
    struct ref_ino *refinop[3];
    struct space_alloc_ctx sctx;
    uint32_t ds_st_mode, ss_st_mode;
    uint64_t ds_st_ino, ss_st_ino;
    uint64_t dde_ino, sde_ino;

    parent = opargs->op_data.link_data.parent;
    name = opargs->op_data.link_data.name;
    newparent = opargs->op_data.link_data.newparent;
    newname = opargs->op_data.link_data.newname;

    pack_u32(db_key, &k, type, TYPE_DIRENT);
    pack_u64(db_key, &k, ino, parent);
    _strlcpy(packed_memb_addr(db_key, &k, name), name,
             packed_memb_size(db_key, name));

    ret = back_end_look_up(opargs->be, &k, NULL, &sde, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    sde_ino = unpack_u64(db_obj_dirent, &sde, ino);

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, sde_ino);

    ret = back_end_look_up(opargs->be, &k, NULL, &ss, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = space_alloc_init_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    ret = set_ref_inode_nodelete(opargs->be, opargs->root_id,
                                 opargs->ref_inodes,
                                 unpack_u64(db_obj_stat, &ss, st_ino), 1);
    if (ret != 0)
        goto err2;

    ss_st_mode = unpack_u32(db_obj_stat, &ss, st_mode);
    ss_st_ino = unpack_u64(db_obj_stat, &ss, st_ino);

    pack_u32(db_key, &k, type, TYPE_DIRENT);
    pack_u64(db_key, &k, ino, newparent);
    _strlcpy(packed_memb_addr(db_key, &k, name), newname,
             packed_memb_size(db_key, name));

    ret = back_end_look_up(opargs->be, &k, NULL, &dde, NULL, 0);
    if (ret != 0) {
        if (ret != 1)
            goto err3;

        /* delete existing link or directory */

        dde_ino = unpack_u64(db_obj_dirent, &dde, ino);

        if (sde_ino == dde_ino) {
            /* POSIX-1.2008, rename, para. 3:
             * If the old argument and the new argument resolve to either the
             * same existing directory entry or different directory entries for
             * the same existing file, rename() shall return successfully and
             * perform no other action. */
            ret = 0;
            goto err3;
        }

        pack_u32(db_key, &k, type, TYPE_STAT);
        pack_u64(db_key, &k, ino, dde_ino);

        ret = back_end_look_up(opargs->be, &k, NULL, &ds, NULL, 0);
        if (ret != 1) {
            if (ret == 0)
                ret = -ENOENT;
            goto err3;
        }

        ds_st_ino = unpack_u64(db_obj_stat, &ds, st_ino);
        ds_st_mode = unpack_u32(db_obj_stat, &ds, st_mode);

        if (!S_ISDIR(ss_st_mode) && S_ISDIR(ds_st_mode)) {
            ret = -EISDIR;
            goto err3;
        }
        if (S_ISDIR(ss_st_mode) && !S_ISDIR(ds_st_mode)) {
            ret = -ENOTDIR;
            goto err3;
        }

        ret = set_ref_inode_nodelete(opargs->be, opargs->root_id,
                                     opargs->ref_inodes, ds_st_ino, 1);
        if (ret != 0)
            goto err3;

        if (S_ISDIR(ds_st_mode)) {
            ret = rem_dir(opargs->be, opargs->root_id, opargs->ref_inodes,
                          ds_st_ino, newparent, newname, 1, 1);
        } else {
            ret = rem_node_link(opargs->be, opargs->root_id, opargs->ref_inodes,
                                ds_st_ino, newparent, newname, NULL,
                                &refinop[0]);
        }
        if (ret != 0) {
            set_ref_inode_nodelete(opargs->be, opargs->root_id,
                                   opargs->ref_inodes, ds_st_ino, 0);
            goto err3;
        }

        existing = 1;

        ret = back_end_look_up(opargs->be, &k, NULL, &ds, NULL, 0);
        if (ret != 1) {
            if (ret == 0)
                ret = -ENOENT;
            goto err4;
        }

        if (unpack_u32(db_obj_stat, &ds, st_nlink) == 0) {
            pack_u32(db_key, &k, type, TYPE_ULINKED_INODE);

            ret = back_end_insert(opargs->be, &k, NULL, 0);
            if (ret != 0)
                goto err4;
        }
    } else
        existing = 0;

    if (S_ISDIR(ss_st_mode)) {
        ret = new_dir_link(opargs->be, opargs->ref_inodes, ss_st_ino, newparent,
                           newname, &refinop[1]);
        if (ret != 0)
            goto err4;

        ret = rem_dir_link(opargs->be, opargs->root_id, opargs->ref_inodes,
                           ss_st_ino, parent, name, &refinop[2]);
    } else {
        ret = new_node_link(opargs->be, opargs->ref_inodes, ss_st_ino,
                            newparent, newname, &refinop[1]);
        if (ret != 0)
            goto err4;

        ret = rem_node_link(opargs->be, opargs->root_id, opargs->ref_inodes,
                            ss_st_ino, parent, name, NULL, &refinop[2]);
    }
    if (ret != 0)
        goto err5;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, newparent);

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err6;
    }

    /* POSIX-1.2008, rename, para. 10:
     * Upon successful completion, rename() shall mark for update the last data
     * modification and last file status change timestamps of the parent
     * directory of each file. */
    set_ts(NULL, packed_st_tim(&ps, m), packed_st_tim(&ps, c));
    if (!existing) {
        pack_u32(db_obj_stat, &ps, num_ents,
                 unpack_u32(db_obj_stat, &ps, num_ents) + 1);
    }

    assert(unpack_u64(db_obj_stat, &ps, st_ino) == unpack_u64(db_key, &k, ino));
    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err6;

    pack_u64(db_key, &k, ino, parent);

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err6;
    }

    /* ", rename, para. 10:
     * " */
    set_ts(NULL, packed_st_tim(&ps, m), packed_st_tim(&ps, c));
    pack_u32(db_obj_stat, &ps, num_ents,
             unpack_u32(db_obj_stat, &ps, num_ents) - 1);

    assert(unpack_u64(db_obj_stat, &ps, st_ino) == unpack_u64(db_key, &k, ino));
    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err6;

    ret = space_alloc_finish_op(&sctx, opargs->be);
    if (ret != 0)
        goto err6;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err6;

    if (existing) {
        set_ref_inode_nodelete(opargs->be, opargs->root_id, opargs->ref_inodes,
                               ds_st_ino, 0);
    }
    set_ref_inode_nodelete(opargs->be, opargs->root_id, opargs->ref_inodes,
                           ss_st_ino, 0);

    return 0;

err6:
    inc_refcnt(opargs->be, opargs->ref_inodes, ss_st_ino, 1, 0, 0, refinop);
err5:
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, refinop[1]);
err4:
    if (existing) {
        if (S_ISDIR(ds_st_mode)) {
            inc_refcnt(opargs->be, opargs->ref_inodes, ds_st_ino, 2, 0, 0,
                       refinop);
            inc_refcnt(opargs->be, opargs->ref_inodes, newparent, 1, 0, 0,
                       refinop);
        } else {
            inc_refcnt(opargs->be, opargs->ref_inodes, ds_st_ino, 1, 0, 0,
                       refinop);
        }
        set_ref_inode_nodelete(opargs->be, opargs->root_id, opargs->ref_inodes,
                               ds_st_ino, 0);
    }
err3:
    set_ref_inode_nodelete(opargs->be, opargs->root_id, opargs->ref_inodes,
                           ss_st_ino, 0);
err2:
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_create_node_link(void *args)
{
    const char *newname;
    int ret;
    inum_t newparent;
    struct db_key k;
    struct db_obj_stat ps;
    struct op_args *opargs = args;
    struct ref_ino *refinop;
    struct space_alloc_ctx sctx;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = space_alloc_init_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    newparent = opargs->op_data.link_data.newparent;
    newname = opargs->op_data.link_data.newname;

    ret = new_node_link(opargs->be, opargs->ref_inodes, opargs->ino, newparent,
                        newname, &refinop);
    if (ret != 0)
        goto err2;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, opargs->ino);

    ret = back_end_look_up(opargs->be, &k, NULL, &opargs->s, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err3;
    }

    /* POSIX-1.2008, link, para. 5:
     * Upon successful completion, link() shall mark for update the last file
     * status change timestamp of the file. */
    do_set_ts(packed_st_tim(&opargs->s, c), NULL);

    ret = back_end_replace(opargs->be, &k, &opargs->s, sizeof(opargs->s));
    if (ret != 0)
        goto err3;

    pack_u64(db_key, &k, ino, newparent);

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err3;
    }

    /* ", link, para. 5:
     * Also, the last data modification and last file status change timestamps
     * of the directory that contains the new entry shall be marked for
     * update. */
    set_ts(NULL, packed_st_tim(&ps, m), packed_st_tim(&ps, c));
    pack_u32(db_obj_stat, &ps, num_ents,
             unpack_u32(db_obj_stat, &ps, num_ents) + 1);

    assert(unpack_u64(db_obj_stat, &ps, st_ino) == unpack_u64(db_key, &k, ino));
    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err3;

    ret = inc_refcnt(opargs->be, opargs->ref_inodes, opargs->ino, 0, 0, 1,
                     opargs->refinop);
    if (ret != 0)
        goto err3;

    ret = space_alloc_finish_op(&sctx, opargs->be);
    if (ret != 0)
        goto err4;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err4;

    return 0;

err4:
    dec_refcnt(opargs->ref_inodes, 0, 0, -1, opargs->refinop[0]);
err3:
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, refinop);
err2:
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_read_entries(void *args)
{
    char *readdir_buf;
    int ret;
    off_t off;
    size_t buflen, bufsize;
    size_t entsize;
    struct back_end_iter *iter;
    struct db_key k;
    struct op_args *opargs = args;
    struct open_dir *odir;

    dump_db(opargs->be);

    ret = back_end_iter_new(&iter, opargs->be);
    if (ret != 0)
        return ret;

    odir = opargs->op_data.readdir_data.odir;

    pack_u32(db_key, &k, type, TYPE_DIRENT);
    pack_u64(db_key, &k, ino, odir->ino);
    _strlcpy(packed_memb_addr(db_key, &k, name), odir->cur_name,
             packed_memb_size(db_key, name));

    off = odir->off;
    buflen = 0;
    bufsize = opargs->op_data.readdir_data.bufsize;

    ret = back_end_iter_search(iter, &k);
    if (ret < 0) {
        if (ret != -EADDRNOTAVAIL)
            goto err;
        goto end2;
    }

    readdir_buf = opargs->op_data.readdir_data.buf;

    while (buflen <= bufsize) {
        const char *name;
        size_t remsize;
        struct stat s;
        union {
            struct db_obj_dirent    de;
            char                    buf[DB_OBJ_MAX_SIZE];
        } buf;

        ret = back_end_iter_get(iter, &k, &buf, NULL);
        if (ret != 0) {
            if (ret != -EADDRNOTAVAIL)
                goto err;
            break;
        }

        if (unpack_u64(db_key, &k, ino) != odir->ino
            || unpack_u32(db_key, &k, type) != TYPE_DIRENT)
            break;

        name = packed_memb_addr(db_key, &k, name);

        _strlcpy(odir->cur_name, name, sizeof(odir->cur_name));

        omemset(&s, 0);
        s.st_ino = unpack_u64(db_obj_dirent, &buf.de, ino);

        remsize = bufsize - buflen;
        entsize = add_direntry(opargs->req, readdir_buf + buflen, remsize, name,
                               &s, off + 1);
        if (entsize > remsize)
            goto end1;

        ret = back_end_iter_next(iter);
        if (ret != 0) {
            if (ret != -EADDRNOTAVAIL)
                goto err;
            break;
        }

        ++off;
        buflen += entsize;
    }

end2:
    odir->cur_name[0] = '\0';
end1:
    back_end_iter_free(iter);
    odir->off = off;
    opargs->op_data.readdir_data.buflen = buflen;
    return 0;

err:
    back_end_iter_free(iter);
    return ret;
}

static int
do_open(void *args)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = args;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, opargs->ino);

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    return inc_refcnt(opargs->be, opargs->ref_inodes, opargs->ino, 0, 1, 0,
                      opargs->refinop);
}

static int
do_read_data(void *args)
{
    int count, iovsz;
    int i;
    int ret;
    int64_t s_st_size;
    off_t off;
    size_t size;
    struct db_key k;
    struct db_obj_stat s;
    struct iovec *iov;
    struct op_args *opargs = args;
    uint64_t firstpgidx, lastpgidx;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, opargs->ino);

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    off = opargs->op_data.rdwr_data.off;

    s_st_size = unpack_i64(db_obj_stat, &s, st_size);

    if (off >= s_st_size) {
        opargs->op_data.rdwr_data.iov = NULL;
        opargs->op_data.rdwr_data.count = 0;
        return 0;
    }

    size = opargs->op_data.rdwr_data.size;

    firstpgidx = off / PG_SIZE;
    trap
        lastpgidx = OFF_MAX / PG_SIZE;
    in {
        lastpgidx = (MIN(addos64s64(off, (off_t)size), s_st_size) - 1)
                    / PG_SIZE;
    }
    count = lastpgidx - firstpgidx + 1;

    if (oecalloc(&iov, count) == NULL)
        return MINUS_ERRNO;

    pack_u32(db_key, &k, type, TYPE_PAGE);

    iovsz = 0;
    for (i = 0; i < count; i++) {
        char buf[PG_SIZE];
        size_t pgoff;
        size_t sz;
        uint64_t k_pgno;

        k_pgno = off / PG_SIZE;

        pack_u64(db_key, &k, pgno, k_pgno);

        pgoff = off - k_pgno * PG_SIZE;

        sz = MIN((off_t)((k_pgno + 1) * PG_SIZE), s_st_size) - off;
        if (sz > size)
            sz = size;

        iov[i].iov_base = do_malloc(sz);
        if (iov[i].iov_base == NULL) {
            ret = MINUS_ERRNO;
            goto err;
        }
        ++iovsz;

        ret = back_end_look_up(opargs->be, &k, NULL, buf, NULL, 0);
        if (ret != 1) {
            if (ret != 0)
                goto err;
            memset(iov[i].iov_base, 0, sz);
        } else
            memcpy(iov[i].iov_base, buf + pgoff, sz);

        iov[i].iov_len = sz;

        off += sz;
        size -= sz;
    }

    opargs->op_data.rdwr_data.iov = iov;
    opargs->op_data.rdwr_data.count = count;

    return 0;

err:
    free_iov(iov, iovsz);
    return ret;
}

static int
do_write_data(void *args)
{
    const char *write_buf;
    int ret;
    off_t off;
    size_t size, write_size;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = args;
    struct space_alloc_ctx sctx;
    uint64_t newpages;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, opargs->ino);

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -ENOENT : ret;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = space_alloc_init_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    pack_u32(db_key, &k, type, TYPE_PAGE);

    write_buf = opargs->op_data.rdwr_data.a_wr;
    off = opargs->op_data.rdwr_data.off;
    size = write_size = opargs->op_data.rdwr_data.size;
    newpages = 0;
    while (size > 0) {
        char buf[PG_SIZE];
        const char *bufp;
        size_t pgoff;
        size_t sz;
        uint64_t k_pgno;

        k_pgno = off / PG_SIZE;

        pack_u64(db_key, &k, pgno, k_pgno);

        pgoff = off - k_pgno * PG_SIZE;

        sz = (k_pgno + 1) * PG_SIZE - off;
        if (sz > size)
            sz = size;

        trap
            sz = OFF_MAX - off;
        in
            addos64s64(off, sz);

        ret = back_end_look_up(opargs->be, &k, NULL, buf, NULL, 0);
        if (ret != 1) {
            if (ret != 0)
                goto err2;

            if (write_buf == null_data)
                bufp = null_data;
            else {
                mempset(mempcpy(mempset(buf, 0, pgoff),
                                write_buf + write_size - size,
                                sz),
                        0,
                        sizeof(buf) - pgoff - sz);
                bufp = buf;
            }

            ret = back_end_insert(opargs->be, &k, bufp, sizeof(buf));
            if (ret != 0)
                goto err2;

            ++newpages;
        } else if (write_buf != null_data) {
            memcpy(buf + pgoff, write_buf + write_size - size, sz);

            ret = back_end_replace(opargs->be, &k, buf, sizeof(buf));
            if (ret != 0)
                goto err2;
        }

        off += sz;
        if (off == OFF_MAX)
            break;
        size -= sz;
    }

    if (off > unpack_i64(db_obj_stat, &s, st_size))
        pack_i64(db_obj_stat, &s, st_size, off);
    pack_i64(db_obj_stat, &s, st_blocks,
             unpack_i64(db_obj_stat, &s, st_blocks) + newpages * BLOCKS_PER_PG);
    /* POSIX-1.2008, write, para. 14:
     * Upon successful completion, where nbyte is greater than 0, write() shall
     * mark for update the last data modification and last file status change
     * timestamps of the file... */
    set_ts(NULL, packed_st_tim(&s, m), packed_st_tim(&s, c));

    pack_u32(db_key, &k, type, TYPE_STAT);

    ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
    if (ret != 0)
        goto err2;

    ret = space_alloc_finish_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err1;

    return 0;

err2:
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_close(void *args)
{
    int ret;
    struct op_args *opargs = args;
    struct ref_ino refino, *refinop;
    struct space_alloc_ctx sctx;

    if (!opargs->ro) {
        ret = back_end_trans_new(opargs->be);
        if (ret != 0)
            return ret;

        ret = space_alloc_init_op(&sctx, opargs->be);
        if (ret != 0)
            goto err1;
    }

    refino.ino = opargs->ino;
    refinop = &refino;

    pthread_mutex_lock(&opargs->ref_inodes->ref_inodes_mtx);
    ret = avl_tree_search(opargs->ref_inodes->ref_inodes, &refinop, &refinop);
    pthread_mutex_unlock(&opargs->ref_inodes->ref_inodes_mtx);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err2;
    }

    ret = unref_inode(opargs->be, opargs->root_id, opargs->ref_inodes, refinop,
                      0, -1, 0, NULL);
    if (ret != 0)
        goto err2;

    if (!opargs->ro) {
        ret = space_alloc_finish_op(&sctx, opargs->be);
        if (ret != 0)
            goto err1;

        ret = back_end_trans_commit(opargs->be);
        if (ret != 0)
            goto err1;
    }

    pthread_mutex_lock(&opargs->ref_inodes->ref_inodes_mtx);
    if (!refinop->nodelete && refinop->nlink == 0 && refinop->refcnt == 0
        && refinop->nlookup == 0) {
        if (avl_tree_delete(opargs->ref_inodes->ref_inodes, &refinop) == 0)
            free(refinop);
    }
    pthread_mutex_unlock(&opargs->ref_inodes->ref_inodes_mtx);

    return 0;

err2:
    if (opargs->ro)
        return ret;
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_sync(void *args)
{
    struct op_args *opargs = args;

    return back_end_sync(opargs->be);
}

static int
do_read_header(void *args)
{
    int ret;
    struct db_key k;
    struct op_args *opargs = args;

    pack_u32(db_key, &k, type, TYPE_HEADER);
    ret = back_end_look_up(opargs->be, &k, NULL, &opargs->hdr, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -EILSEQ : ret;

    return 0;
}

static int
do_setxattr(void *args)
{
    const char *value;
    int flags;
    int ret;
    size_t size;
    struct db_key k;
    struct op_args *opargs = args;
    struct space_alloc_ctx sctx;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = space_alloc_init_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    flags = opargs->op_data.xattr_data.flags;

    pack_u32(db_key, &k, type, TYPE_XATTR);
    pack_u64(db_key, &k, ino, opargs->ino);
    _strlcpy(packed_memb_addr(db_key, &k, name),
             opargs->op_data.xattr_data.name, packed_memb_size(db_key, name));

    value = opargs->op_data.xattr_data.value_a_wr;
    size = opargs->op_data.xattr_data.size;

    if (flags == 0 || flags == XATTR_CREATE) {
        ret = back_end_insert(opargs->be, &k, value, size);
        if (ret == 0)
            goto end;
        if (ret != -EADDRINUSE || flags == XATTR_CREATE)
            goto err2;
    } else if (flags != XATTR_REPLACE) {
        ret = -EINVAL;
        goto err2;
    }

    ret = back_end_replace(opargs->be, &k, value, size);
    if (ret != 0)
        goto err2;

end:

    ret = space_alloc_finish_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err1;

    return 0;

err2:
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_getxattr(void *args)
{
    char *value = NULL;
    int ret;
    size_t size, valsize;
    struct db_key k;
    struct op_args *opargs = args;

    size = opargs->op_data.xattr_data.size;

    pack_u32(db_key, &k, type, TYPE_XATTR);
    pack_u64(db_key, &k, ino, opargs->ino);
    _strlcpy(packed_memb_addr(db_key, &k, name),
             opargs->op_data.xattr_data.name, packed_memb_size(db_key, name));

    ret = back_end_look_up(opargs->be, &k, NULL, NULL, &valsize, 0);
    if (ret != 1)
        return ret == 0 ? -EADDRNOTAVAIL : ret;
    if (size == 0)
        goto end;
    if (size < valsize)
        return -ERANGE;

    if (valsize == 0)
        goto end;

    value = do_malloc(valsize);
    if (value == NULL)
        return MINUS_ERRNO;

    ret = back_end_look_up(opargs->be, &k, NULL, value, NULL, 0);
    if (ret != 1) {
        free(value);
        return ret == 0 ? -EIO : ret;
    }

end:
    opargs->op_data.xattr_data.value_a_rd = value;
    opargs->op_data.xattr_data.size = valsize;
    return 0;
}

static int
do_listxattr(void *args)
{
    char *k_name;
    char *value;
    int ret;
    size_t bufsize;
    size_t len, size;
    struct back_end_iter *iter;
    struct db_key k;
    struct op_args *opargs = args;

    ret = back_end_iter_new(&iter, opargs->be);
    if (ret != 0)
        return ret;

    k_name = packed_memb_addr(db_key, &k, name);

    pack_u32(db_key, &k, type, TYPE_XATTR);
    pack_u64(db_key, &k, ino, opargs->ino);
    k_name[0] = '\0';

    value = NULL;
    len = size = 0;

    ret = back_end_iter_search(iter, &k);
    if (ret < 0) {
        if (ret != -EADDRNOTAVAIL)
            goto err1;
        goto end;
    }

    for (;;) {
        ret = back_end_iter_get(iter, &k, NULL, NULL);
        if (ret != 0) {
            if (ret != -EADDRNOTAVAIL)
                goto err2;
            break;
        }

        if (unpack_u64(db_key, &k, ino) != opargs->ino
            || unpack_u32(db_key, &k, type) != TYPE_XATTR)
            break;

        ret = add_xattr_name(&value, &len, &size, k_name);
        if (ret != 0)
            goto err2;

        ret = back_end_iter_next(iter);
        if (ret != 0) {
            if (ret != -EADDRNOTAVAIL)
                goto err2;
            break;
        }
    }

end:

    bufsize = opargs->op_data.xattr_data.size;

    if (bufsize == 0) {
        if (value != NULL)
            free(value);
    } else if (bufsize < len) {
        ret = -ERANGE;
        goto err2;
    }

    back_end_iter_free(iter);

    opargs->op_data.xattr_data.value_a_rd = value;
    opargs->op_data.xattr_data.size = len;

    return 0;

err2:
    if (value != NULL)
        free(value);
err1:
    back_end_iter_free(iter);
    return ret;
}

static int
do_removexattr(void *args)
{
    int ret;
    struct db_key k;
    struct op_args *opargs = args;
    struct space_alloc_ctx sctx;

    pack_u32(db_key, &k, type, TYPE_XATTR);
    pack_u64(db_key, &k, ino, opargs->ino);
    _strlcpy(packed_memb_addr(db_key, &k, name),
             opargs->op_data.xattr_data.name, packed_memb_size(db_key, name));

    ret = back_end_look_up(opargs->be, &k, NULL, NULL, NULL, 0);
    if (ret != 1)
        return ret == 0 ? -EADDRNOTAVAIL : ret;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = space_alloc_init_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    ret = back_end_delete(opargs->be, &k);
    if (ret != 0)
        goto err2;

    ret = space_alloc_finish_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err1;

    return 0;

err2:
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_access(void *args)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = args;

    if (opargs->op_data.mask & F_OK) {
        pack_u32(db_key, &k, type, TYPE_STAT);
        pack_u64(db_key, &k, ino, opargs->ino);

        ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
        if (ret != 1)
            return ret == 0 ? -ENOENT : ret;
    }

    return 0;
}

static int
do_create(void *args)
{
    const char *name;
    const struct ctx *ctx;
    int ret;
    inum_t parent;
    struct db_key k;
    struct db_obj_stat ps;
    struct op_args *opargs = args;
    struct space_alloc_ctx sctx;

    ctx = opargs->ctx;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = space_alloc_init_op(&sctx, opargs->be);
    if (ret != 0)
        goto err1;

    parent = opargs->op_data.mknod_data.parent;
    name = opargs->op_data.mknod_data.name;

    /* POSIX-1.2008, open, para. 7:
     * If O_CREAT is set and the file did not previously exist, upon successful
     * completion, open() shall mark for update the last data access, last data
     * modification, and last file status change timestamps of the file... */
    ret = new_node(opargs->be, opargs->ref_inodes, parent, name, ctx->uid,
                   ctx->gid, opargs->op_data.mknod_data.mode & ~ctx->umask, 0,
                   0, &opargs->attr, opargs->refinop, 1);
    if (ret != 0)
        goto err2;

    pack_u32(db_key, &k, type, TYPE_STAT);
    pack_u64(db_key, &k, ino, parent);

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err3;
    }

    /* ", open, para. 7:
     * If O_CREAT is set and the file did not previously exist, upon successful
     * completion, open() shall mark for update...the last data modification and
     * last file status change timestamps of the parent directory. */
    set_ts(NULL, packed_st_tim(&ps, m), packed_st_tim(&ps, c));

    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err3;

    ret = inc_refcnt(opargs->be, opargs->ref_inodes, opargs->attr.st_ino, 0, 1,
                     0, &opargs->refinop[2]);
    if (ret != 0)
        goto err3;

    ret = space_alloc_finish_op(&sctx, opargs->be);
    if (ret != 0)
        goto err4;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err4;

    dump_db(opargs->be);

    return 0;

err4:
    dec_refcnt(opargs->ref_inodes, 0, -1, 0, opargs->refinop[2]);
err3:
    dec_refcnt(opargs->ref_inodes, 0, 0, -1, opargs->refinop[1]);
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, opargs->refinop[0]);
err2:
    space_alloc_abort_op(opargs->be);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static void
set_trans_cb(void *args, void (*cb)(int, int, int, void *), void *ctx)
{
    struct db_args *dbargs = args;

    dbargs->trans_cb = cb;
    dbargs->trans_ctx = ctx;
}

static int
simplefs_init_prepare(void *rctx, struct session *sess, inum_t root_id)
{
    int ret;
    struct db_args dbargs;
    struct db_key k;
    struct db_obj_free_ino freeino;
    struct db_obj_header hdr;
    struct fspriv *priv;
    struct fuse_cache_args args;
    struct mount_data *md = rctx;
    struct ref_ino *refinop[4];

    (void)sess;

    if (oemalloc(&priv) == NULL)
        return MINUS_ERRNO;

    priv->root_id = root_id;
    priv->wb_err = 0;

    ret = fifo_new(&priv->queue, sizeof(struct queue_elem *), 1024);
    if (ret != 0)
        goto err1;

    dbargs.wd = md->wd;
    dbargs.db_pathname = md->db_pathname == NULL
                         ? DB_PATHNAME : md->db_pathname;
    dbargs.db_mode = ACC_MODE_DEFAULT;
    dbargs.ro = md->ro;
    dbargs.lkw = md->lkw;
    dbargs.sync_cb = &sync_cb;
    dbargs.sync_ctx = priv;
    dbargs.hdrlen = dbargs.jlen = 0;
    dbargs.blkdevsz = 0;

    args.ops = BACK_END_DBM;
    args.set_trans_cb = &set_trans_cb;
    args.disable_iter_commit = &back_end_dbm_disable_iter_commit;
    args.sync_cb = &sync_cb;
    args.sync_ctx = priv;
    args.args = &dbargs;

    ret = file_tab_init(&priv->ftab);
    if (ret != 0)
        goto err2;

    ret = avl_tree_new(&priv->ref_inodes.ref_inodes, sizeof(struct ref_ino *),
                       &ref_inode_cmp, 0, NULL, NULL, NULL);
    if (ret != 0)
        goto err3;
    ret = -pthread_mutex_init(&priv->ref_inodes.ref_inodes_mtx, NULL);
    if (ret != 0)
        goto err4;

    /* Note: The following calls to back_end_open() and back_end_create()
       prevent simultaneous mounts of the same block device or file by other
       simplefs daemons */

    ret = back_end_open(&priv->be, sizeof(struct db_key), BACK_END_FUSE_CACHE,
                        &db_key_cmp, &args);
    if (ret != 0) {
        size_t db_hdrlen;
        struct space_alloc_ctx sctx;
        uint64_t *freeino_used_ino;

        if (ret != -ENOENT)
            goto err5;

        if (dbargs.ro) {
            infomsg("Warning: Ignoring read-only mount flag (creating file "
                    "system)\n");
        }

        sctx.delta = 0;

        dbargs.alloc_cb.alloc_cb = &space_alloc_cb;
        dbargs.alloc_cb.alloc_cb_ctx = &sctx;

        ret = back_end_create(&priv->be, sizeof(struct db_key),
                              BACK_END_FUSE_CACHE, &db_key_cmp, &args);
        if (ret != 0)
            goto err5;

        ret = back_end_ctl(priv->be, BACK_END_DBM_OP_GET_HDR_LEN, &db_hdrlen);
        if (ret != 0)
            goto err6;
        pack_u64(db_obj_header, &hdr, usedbytes,
                 dbargs.hdrlen + db_hdrlen + sctx.delta + dbargs.jlen);

        ret = space_alloc_init_op(&sctx, priv->be);
        if (ret != 0)
            goto err6;

        pack_u32(db_key, &k, type, TYPE_HEADER);
        pack_u64(db_obj_header, &hdr, version, FMT_VERSION);
        pack_u64(db_obj_header, &hdr, numinodes, 1);
        ret = back_end_insert(priv->be, &k, &hdr, sizeof(hdr));
        if (ret != 0)
            goto err7;

        freeino_used_ino = (uint64_t *)packed_memb_addr(db_obj_free_ino,
                                                        &freeino, used_ino);

        pack_u32(db_key, &k, type, TYPE_FREE_INO);
        pack_u64(db_key, &k, ino, root_id);
        memset(freeino_used_ino, 0,
               packed_memb_size(db_obj_free_ino, used_ino));
        used_ino_set(freeino_used_ino, root_id, root_id, 1);
        pack_u8(db_obj_free_ino, &freeino, flags, FREE_INO_LAST_USED);
        ret = back_end_insert(priv->be, &k, &freeino, sizeof(freeino));
        if (ret != 0)
            goto err7;

        /* create root directory */
        ret = new_dir(priv->be, root_id, &priv->ref_inodes, 0, NULL, getuid(),
                      getgid(), ROOT_DIR_INIT_PERMS, NULL, refinop, 0);
        if (ret != 0)
            goto err7;

        ret = space_alloc_finish_op(&sctx, priv->be);
        if (ret != 0)
            goto err6;

        ret = back_end_sync(priv->be);
        if (ret != 0)
            goto err6;
    } else {
        pack_u32(db_key, &k, type, TYPE_HEADER);

        ret = back_end_look_up(priv->be, &k, NULL, &hdr, NULL, 0);
        if (ret != 1) {
            if (ret == 0)
                ret = -EILSEQ;
            goto err6;
        }

        /* Note: Any space allocation changes must be handled by the format
           updating code as necessary */
        ret = compat_init(priv->be, unpack_u64(db_obj_header, &hdr, version),
                          FMT_VERSION, dbargs.hdrlen, dbargs.jlen, md->ro,
                          md->fmtconv);
        if (ret != 0)
            goto err6;

        /* FIXME: validate root I-node number */

        if (!dbargs.ro) {
            ret = remove_ulinked_nodes(priv->be, root_id);
            if (ret != 0)
                goto err6;
        }
    }

    priv->blkdev = dbargs.blkdev;
    priv->blkdevsz = dbargs.blkdevsz;

    fuse_cache_set_dump_cb(*(struct fuse_cache **)priv->be, &dump_db_obj, NULL);

    md->priv = priv;

    ret = -pthread_create(&priv->worker_td, NULL, &worker_td, md);
    if (ret != 0)
        goto err6;

    /* root I-node implicitly looked up on completion of init request */
    ret = inc_refcnt(priv->be, &priv->ref_inodes, root_id, 0, 0, 1,
                     &refinop[0]);
    if (ret != 0) {
        join_worker(priv);
        goto err6;
    }

    if (md->wd != -1) {
        close(md->wd);
        md->wd = -1;
    }

    return 0;

err7:
    space_alloc_abort_op(priv->be);
err6:
    back_end_close(priv->be);
err5:
    pthread_mutex_destroy(&priv->ref_inodes.ref_inodes_mtx);
err4:
    avl_tree_free(priv->ref_inodes.ref_inodes);
err3:
    file_tab_destroy(priv->ftab);
err2:
    fifo_free(priv->queue);
err1:
    free(priv);
    return ret;
}

static void
simplefs_init(void *rctx, struct session *sess, inum_t root_id)
{
    struct mount_data *md = rctx;

    (void)sess;
    (void)root_id;

    if (md->pipefd != -1) {
        do_write(md->pipefd, SIMPLEFS_MOUNT_PIPE_MSG_OK,
                 sizeof(SIMPLEFS_MOUNT_PIPE_MSG_OK), 4096);
    }
}

static int
simplefs_destroy_finish(void *userdata)
{
    avl_tree_walk_ctx_t wctx = NULL;
    int ret, tmp;
    struct fspriv *priv;
    struct free_ref_inodes_ctx fctx;
    struct mount_data *md = userdata;

    priv = md->priv;

    ret = join_worker(priv);

    fctx.priv = priv;
    fctx.nowrite = md->ro;
    fctx.err = 0;
    tmp = avl_tree_walk(priv->ref_inodes.ref_inodes, NULL, &free_ref_inodes_cb,
                        &fctx, &wctx);
    if (fctx.err)
        ret = fctx.err;
    else if (tmp != 0)
        ret = tmp;

    avl_tree_free(priv->ref_inodes.ref_inodes);

    pthread_mutex_destroy(&priv->ref_inodes.ref_inodes_mtx);

    file_tab_destroy(priv->ftab);

    tmp = back_end_close(priv->be);
    if (tmp != 0)
        ret = tmp;

    /* Note: Past this point, other simplefs daemons mounting the same block
       device or file may start successfully */

    fifo_free(priv->queue);

    free(priv);

    return ret;
}

static void
simplefs_lookup(void *req, inum_t parent, const char *name)
{
    int ret;
    struct entry_param e;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    pack_u32(db_key, &opargs.k, type, TYPE_DIRENT);
    pack_u64(db_key, &opargs.k, ino, parent);
    _strlcpy(packed_memb_addr(db_key, &opargs.k, name), name,
             packed_memb_size(db_key, name));

    opargs.op_data.inc_lookup_cnt = 1;

    ret = do_queue_op(priv, &do_look_up, &opargs);
    if (ret != 0 && ret != 1)
        goto err;
    omemset(&e, 0);
    if (ret == 1) {
        e.ino = unpack_u64(db_obj_stat, &opargs.s, st_ino);
        deserialize_stat(&e.attr, &opargs.s);
        if (S_ISDIR(e.attr.st_mode))
            e.attr.st_size = unpack_u32(db_obj_stat, &opargs.s, num_ents);
    }
    e.generation = 1;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;

    ret = reply_entry(req, &e);
    if (ret != 0) {
        if (e.ino != 0) {
            /* In the unlikely event that reply_entry() returns an error, this
               code will revert the changes made to the reference-counting
               structures in memory by do_look_up() without performing any
               necessary file deletion if all reference counts become 0. This
               will result in a resource leak in the file system. */
            dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop[0]);
        }
        if (ret != -ENOENT)
            goto err;
    }

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_forget(void *req, inum_t ino, uint64_t nlookup)
{
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ro = md->ro;
    opargs.root_id = priv->root_id;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    opargs.op_data.nlookup = nlookup;

    do_queue_op(priv, &do_forget, &opargs);

    reply_none(req);
}

static void
simplefs_getattr(void *req, inum_t ino, struct file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;
    struct stat attr;

    (void)fi; /* fi is always NULL */

    priv = md->priv;

    opargs.be = priv->be;

    pack_u32(db_key, &opargs.k, type, TYPE_STAT);
    pack_u64(db_key, &opargs.k, ino, ino);

    opargs.op_data.inc_lookup_cnt = 0;

    ret = do_queue_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err;
    }

    deserialize_stat(&attr, &opargs.s);
    if (S_ISDIR(attr.st_mode))
        attr.st_size = unpack_u32(db_obj_stat, &opargs.s, num_ents);

    ret = reply_attr(req, &attr, CACHE_TIMEOUT);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_setattr(void *req, inum_t ino, struct stat *attr, int to_set,
                 struct file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    /* VFS handles file descriptor access mode check for ftruncate() on Linux */
    (void)fi;

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;
    opargs.attr = *attr;

    opargs.op_data.to_set = to_set;

    ret = do_queue_op(priv, &do_setattr, &opargs);
    if (ret != 0)
        goto err;

    ret = reply_attr(req, &opargs.attr, CACHE_TIMEOUT);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_readlink(void *req, inum_t ino)
{
    char *link;
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    ret = do_queue_op(priv, &do_read_symlink, &opargs);
    if (ret != 0)
        goto err;

    link = opargs.op_data.rdwr_data.a_rd;

    ret = reply_readlink(req, link);
    free(link);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_mknod(void *req, inum_t parent, const char *name, mode_t mode,
               dev_t rdev)
{
    int ret;
    struct entry_param e;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.ctx = req_ctx(req);

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = parent;

    opargs.op_data.mknod_data.name = name;
    opargs.op_data.mknod_data.mode = mode;
    opargs.op_data.mknod_data.rdev = rdev;

    ret = do_queue_op(priv, &do_create_node, &opargs);
    if (ret != 0)
        goto err;

    omemset(&e, 0);
    e.ino = opargs.attr.st_ino;
    e.generation = 1;
    e.attr = opargs.attr;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;
    ret = reply_entry(req, &e);
    if (ret != 0) {
        dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop[1]);
        if (ret != -ENOENT)
            goto err;
    }

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_mkdir(void *req, inum_t parent, const char *name, mode_t mode)
{
    int ret;
    struct entry_param e;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.ctx = req_ctx(req);

    opargs.be = priv->be;
    opargs.root_id = priv->root_id;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = parent;

    opargs.op_data.mknod_data.name = name;
    opargs.op_data.mknod_data.mode = mode;

    ret = do_queue_op(priv, &do_create_dir, &opargs);
    if (ret != 0)
        goto err;

    omemset(&e, 0);
    e.ino = opargs.attr.st_ino;
    e.generation = 1;
    e.attr = opargs.attr;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;
    ret = reply_entry(req, &e);
    if (ret != 0) {
        dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop[3]);
        if (ret != -ENOENT)
            goto err;
    }

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_unlink(void *req, inum_t parent, const char *name)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;
    opargs.root_id = priv->root_id;
    opargs.ref_inodes = &priv->ref_inodes;

    pack_u32(db_key, &opargs.k, type, TYPE_DIRENT);
    pack_u64(db_key, &opargs.k, ino, parent);
    _strlcpy(packed_memb_addr(db_key, &opargs.k, name), name,
             packed_memb_size(db_key, name));

    opargs.op_data.inc_lookup_cnt = 0;

    ret = do_queue_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err;
    }

    opargs.ino = unpack_u64(db_obj_stat, &opargs.s, st_ino);

    opargs.op_data.link_data.parent = parent;
    opargs.op_data.link_data.name = name;

    ret = do_queue_op(priv, &do_remove_node_link, &opargs);
    if (ret != 0)
        goto err;

    ret = reply_err(req, 0);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_rmdir(void *req, inum_t parent, const char *name)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        ret = EINVAL;
        goto err;
    }

    priv = md->priv;

    opargs.be = priv->be;
    opargs.root_id = priv->root_id;
    opargs.ref_inodes = &priv->ref_inodes;

    pack_u32(db_key, &opargs.k, type, TYPE_DIRENT);
    pack_u64(db_key, &opargs.k, ino, parent);
    _strlcpy(packed_memb_addr(db_key, &opargs.k, name), name,
             packed_memb_size(db_key, name));

    opargs.op_data.inc_lookup_cnt = 0;

    ret = do_queue_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err;
    }

    opargs.ino = unpack_u64(db_obj_stat, &opargs.s, st_ino);

    if (opargs.ino == priv->root_id) {
        ret = -EBUSY;
        goto err;
    }

    opargs.op_data.link_data.parent = parent;
    opargs.op_data.link_data.name = name;

    ret = do_queue_op(priv, &do_remove_dir, &opargs);
    if (ret != 0)
        goto err;

    ret = reply_err(req, 0);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_symlink(void *req, const char *link, inum_t parent, const char *name)
{
    int ret;
    struct entry_param e;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.ctx = req_ctx(req);

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.op_data.mknod_data.parent = parent;
    opargs.op_data.mknod_data.name = name;
    opargs.op_data.mknod_data.link = link;

    ret = do_queue_op(priv, &do_create_symlink, &opargs);
    if (ret != 0)
        goto err;

    omemset(&e, 0);
    e.ino = opargs.attr.st_ino;
    e.generation = 1;
    e.attr = opargs.attr;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;
    ret = reply_entry(req, &e);
    if (ret != 0) {
        dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop[1]);
        if (ret != -ENOENT)
            goto err;
    }

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_rename(void *req, inum_t parent, const char *name, inum_t newparent,
                const char *newname)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0
        || strcmp(newname, ".") == 0 || strcmp(newname, "..") == 0) {
        ret = EINVAL;
        goto err;
    }

    priv = md->priv;

    opargs.be = priv->be;
    opargs.root_id = priv->root_id;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.op_data.link_data.parent = parent;
    opargs.op_data.link_data.name = name;
    opargs.op_data.link_data.newparent = newparent;
    opargs.op_data.link_data.newname = newname;

    ret = do_queue_op(priv, &do_rename, &opargs);
    if (ret != 0)
        goto err;

    ret = reply_err(req, 0);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_link(void *req, inum_t ino, inum_t newparent, const char *newname)
{
    int ret;
    struct entry_param e;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    opargs.op_data.link_data.newparent = newparent;
    opargs.op_data.link_data.newname = newname;

    ret = do_queue_op(priv, &do_create_node_link, &opargs);
    if (ret != 0)
        goto err;

    omemset(&e, 0);
    e.ino = unpack_u64(db_obj_stat, &opargs.s, st_ino);
    e.generation = 1;
    deserialize_stat(&e.attr, &opargs.s);
    if (S_ISDIR(e.attr.st_mode))
        e.attr.st_size = unpack_u32(db_obj_stat, &opargs.s, num_ents);
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;

    ret = reply_entry(req, &e);
    if (ret != 0) {
        dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop[0]);
        if (ret != -ENOENT)
            goto err;
    }

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_open(void *req, inum_t ino, struct file_info *fi)
{
    int interrupted = 0;
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;
    struct open_file *ofile;
    uint64_t desc;

    if (md->ro && (fi->flags & O_ACCMODE) != O_RDONLY) {
        ret = -EROFS;
        goto err1;
    }

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ro = md->ro;
    opargs.root_id = priv->root_id;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    if (oemalloc(&ofile) == NULL) {
        ret = MINUS_ERRNO;
        goto err1;
    }

    ret = file_tab_get(priv->ftab, ofile, &desc);
    if (ret != 0)
        goto err2;

    ret = do_queue_op(priv, &do_open, &opargs);
    if (ret != 0)
        goto err3;

    ofile->ino = ino;

    fi->fh = desc;
    fi->keep_cache = KEEP_CACHE_OPEN;

    ret = reply_open(req, fi);
    if (ret != 0) {
        if (ret == -ENOENT)
            interrupted = 1;
        goto err4;
    }

    return;

err4:
    do_queue_op(priv, &do_close, &opargs);
err3:
    file_tab_put(priv->ftab, desc);
err2:
    free(ofile);
err1:
    if (!interrupted)
        reply_err(req, -ret);
}

static void
simplefs_read(void *req, inum_t ino, size_t size, off_t off,
              struct file_info *fi)
{
    int count;
    int ret;
    struct fspriv *priv;
    struct iovec *iov;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    (void)fi; /* VFS handles file descriptor access mode check on Linux */

    if (size == 0) {
        ret = reply_iov(req, NULL, 0);
        if (ret != 0 && ret != -ENOENT)
            goto err;
        return;
    }

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.op_data.rdwr_data.size = size;
    opargs.op_data.rdwr_data.off = off;

    ret = do_queue_op(priv, &do_read_data, &opargs);
    if (ret != 0)
        goto err;

    iov = opargs.op_data.rdwr_data.iov;
    count = opargs.op_data.rdwr_data.count;

    ret = reply_iov(req, iov, count);
    free_iov(iov, count);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_write(void *req, inum_t ino, const char *buf, size_t size, off_t off,
               struct file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    /* VFS handles file descriptor access mode check on Linux */
    /* fi->fh guessed if called by writeback */
    (void)fi;

    if (size == 0) {
        ret = reply_write(req, 0);
        if (ret != 0 && ret != -ENOENT)
            goto err;
        return;
    }

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.op_data.rdwr_data.a_wr = buf;
    opargs.op_data.rdwr_data.size = size;
    opargs.op_data.rdwr_data.off = off;

    ret = do_queue_op(priv, &do_write_data, &opargs);
    if (ret != 0)
        goto err;

    ret = reply_write(req, size);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_flush(void *req, inum_t ino, struct file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);

    (void)ino;
    (void)fi;

    priv = md->priv;

    ret = reply_err(req, -priv->wb_err);
    if (ret != 0 && ret != -ENOENT)
        reply_err(req, -ret);
}

static void
simplefs_opendir(void *req, inum_t ino, struct file_info *fi)
{
    int interrupted = 0;
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;
    struct open_dir *odir;
    uint64_t desc;

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ro = md->ro;
    opargs.root_id = priv->root_id;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    if (oemalloc(&odir) == NULL) {
        ret = MINUS_ERRNO;
        goto err1;
    }

    ret = file_tab_get(priv->ftab, odir, &desc);
    if (ret != 0)
        goto err2;

    ret = do_queue_op(priv, &do_open, &opargs);
    if (ret != 0)
        goto err3;

    odir->ino = ino;
    odir->cur_name[0] = '\0';
    odir->off = 0;

    fi->fh = desc;
    fi->keep_cache = KEEP_CACHE_OPEN;

    ret = reply_open(req, fi);
    if (ret != 0) {
        if (ret == -ENOENT)
            interrupted = 1;
        goto err4;
    }

    return;

err4:
    do_queue_op(priv, &do_close, &opargs);
err3:
    file_tab_put(priv->ftab, desc);
err2:
    free(odir);
err1:
    if (!interrupted)
        reply_err(req, -ret);
}

static void
simplefs_readdir(void *req, inum_t ino, size_t size, off_t off,
                 struct file_info *fi)
{
    char *buf;
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;
    struct open_dir *odir;

    (void)ino;

    priv = md->priv;

    odir = file_tab_look_up(priv->ftab, fi->fh);

    if (off == 0) { /* newly-opened directory stream or rewinddir() */
        odir->cur_name[0] = '\0';
        odir->off = 0;
    } else if (off == odir->off) {
        if (odir->cur_name[0] == '\0') { /* end of directory stream */
            ret = reply_buf(req, NULL, 0);
            if (ret != 0 && ret != -ENOENT)
                goto err;
            return;
        }
    } else { /* seekdir() to position other than 0 or current stream position */
        ret = -EOPNOTSUPP;
        goto err;
    }

    buf = do_malloc(size);
    if (buf == NULL) {
        ret = -errno;
        goto err;
    }

    opargs.req = req;

    opargs.be = priv->be;

    opargs.op_data.readdir_data.odir = odir;
    opargs.op_data.readdir_data.buf = buf;
    opargs.op_data.readdir_data.bufsize = size;

    ret = do_queue_op(priv, &do_read_entries, &opargs);
    if (ret != 0) {
        free(buf);
        goto err;
    }

    ret = reply_buf(req, buf, opargs.op_data.readdir_data.buflen);
    free(buf);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_release(void *req, inum_t ino, struct file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;
    struct open_file *ofile;

    priv = md->priv;

    ofile = file_tab_look_up(priv->ftab, fi->fh);

    opargs.be = priv->be;
    opargs.ro = md->ro;
    opargs.root_id = priv->root_id;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    ret = do_queue_op(priv, &do_close, &opargs);

    file_tab_put(priv->ftab, fi->fh);

    free(ofile);

    reply_err(req, -ret);
}

static void
simplefs_fsync(void *req, inum_t ino, int datasync, struct file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    (void)ino;
    (void)datasync;
    (void)fi;

    priv = md->priv;

    if (priv->wb_err)
        ret = priv->wb_err;
    else {
        opargs.be = priv->be;

        ret = do_queue_op(priv, &do_sync, &opargs);
        if (ret == 0)
            ret = priv->wb_err;
    }

    ret = reply_err(req, -ret);
    if (ret != 0 && ret != -ENOENT)
        reply_err(req, -ret);
}

static void
simplefs_releasedir(void *req, inum_t ino, struct file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;
    struct open_dir *odir;

    priv = md->priv;

    odir = file_tab_look_up(priv->ftab, fi->fh);

    opargs.be = priv->be;
    opargs.ro = md->ro;
    opargs.root_id = priv->root_id;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    ret = do_queue_op(priv, &do_close, &opargs);

    file_tab_put(priv->ftab, fi->fh);

    free(odir);

    reply_err(req, -ret);
}

static void
simplefs_fsyncdir(void *req, inum_t ino, int datasync, struct file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    (void)ino;
    (void)datasync;
    (void)fi;

    priv = md->priv;

    if (priv->wb_err)
        ret = priv->wb_err;
    else {
        opargs.be = priv->be;

        ret = do_queue_op(priv, &do_sync, &opargs);
        if (ret == 0)
            ret = priv->wb_err;
    }

    ret = reply_err(req, -ret);
    if (ret != 0 && ret != -ENOENT)
        reply_err(req, -ret);
}

static void
simplefs_statfs(void *req, inum_t ino)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;
    struct statvfs stbuf;

    (void)ino;

    priv = md->priv;

    opargs.be = priv->be;

    ret = do_queue_op(priv, &do_read_header, &opargs);
    if (ret != 0)
        goto err;

    if (priv->blkdev) {
        stbuf.f_blocks = priv->blkdevsz / PG_SIZE;
        stbuf.f_bfree = stbuf.f_bavail
            = (priv->blkdevsz
               - unpack_u64(db_obj_header, &opargs.hdr, usedbytes))
              / PG_SIZE;
    } else {
        if (statvfs(".", &stbuf) == -1) {
            ret = -errno;
            goto err;
        }

        stbuf.f_blocks = stbuf.f_blocks * stbuf.f_frsize / PG_SIZE;
        stbuf.f_bfree = stbuf.f_bfree * stbuf.f_bsize / PG_SIZE;
        stbuf.f_bavail = stbuf.f_bavail * stbuf.f_bsize / PG_SIZE;
    }

    stbuf.f_bsize = PG_SIZE;
    stbuf.f_frsize = PG_SIZE;

    stbuf.f_files = (fsfilcnt_t)ULONG_MAX;
    stbuf.f_ffree = stbuf.f_favail
        = (fsfilcnt_t)(stbuf.f_files - unpack_u64(db_obj_header, &opargs.hdr,
                                                  numinodes));

    stbuf.f_fsid = 0;

    stbuf.f_flag = 0;

    stbuf.f_namemax = NAME_MAX;

    ret = reply_statfs(req, &stbuf);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_setxattr(void *req, inum_t ino, const char *name, const char *value,
                  size_t size, int flags)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.op_data.xattr_data.name = name;
    opargs.op_data.xattr_data.value_a_wr = value;
    opargs.op_data.xattr_data.size = size;
    opargs.op_data.xattr_data.flags = flags;

    ret = do_queue_op(priv, &do_setxattr, &opargs);
    if (ret != 0)
        goto err;

    ret = reply_err(req, -ret);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_getxattr(void *req, inum_t ino, const char *name, size_t size)
{
    char *value;
    int ret;
    size_t valsize;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.op_data.xattr_data.name = name;
    opargs.op_data.xattr_data.size = size;

    ret = do_queue_op(priv, &do_getxattr, &opargs);
    if (ret != 0) {
        if (ret == -EADDRNOTAVAIL)
            ret = -ENOATTR;
        goto err;
    }

    valsize = opargs.op_data.xattr_data.size;

    if (size == 0) {
        ret = reply_xattr(req, valsize);
        if (ret != 0 && ret != -ENOENT)
            goto err;
        return;
    }

    value = opargs.op_data.xattr_data.value_a_rd;

    ret = reply_buf(req, value, valsize);

    if (value != NULL)
        free(value);

    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_listxattr(void *req, inum_t ino, size_t size)
{
    char *value;
    int ret;
    size_t bufsize;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.op_data.xattr_data.size = size;

    ret = do_queue_op(priv, &do_listxattr, &opargs);
    if (ret != 0)
        goto err;

    bufsize = opargs.op_data.xattr_data.size;

    if (size == 0) {
        ret = reply_xattr(req, bufsize);
        if (ret != 0 && ret != -ENOENT)
            goto err;
        return;
    }

    value = opargs.op_data.xattr_data.value_a_rd;

    ret = reply_buf(req, value, bufsize);

    if (value != NULL)
        free(value);

    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_removexattr(void *req, inum_t ino, const char *name)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.op_data.xattr_data.name = name;

    ret = do_queue_op(priv, &do_removexattr, &opargs);
    if (ret != 0) {
        if (ret == -EADDRNOTAVAIL)
            ret = -ENOATTR;
        goto err;
    }

    ret = reply_err(req, -ret);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_access(void *req, inum_t ino, int mask)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.op_data.mask = mask;

    ret = do_queue_op(priv, &do_access, &opargs);
    if (ret != 0)
        goto err;

    ret = reply_err(req, -ret);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

static void
simplefs_create(void *req, inum_t parent, const char *name, mode_t mode,
                struct file_info *fi)
{
    int interrupted = 0;
    int ret;
    struct entry_param e;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;
    struct open_file *ofile;
    uint64_t desc;

    if (md->ro && (fi->flags & O_ACCMODE) != O_RDONLY) {
        ret = -EROFS;
        goto err1;
    }

    priv = md->priv;

    opargs.ctx = req_ctx(req);

    opargs.be = priv->be;
    opargs.ro = md->ro;
    opargs.root_id = priv->root_id;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.op_data.mknod_data.parent = parent;
    opargs.op_data.mknod_data.name = name;
    opargs.op_data.mknod_data.mode = mode;

    if (oemalloc(&ofile) == NULL) {
        ret = MINUS_ERRNO;
        goto err1;
    }

    ret = file_tab_get(priv->ftab, ofile, &desc);
    if (ret != 0)
        goto err2;

    ret = do_queue_op(priv, &do_create, &opargs);
    if (ret != 0)
        goto err3;

    ofile->ino = opargs.attr.st_ino;

    fi->fh = desc;
    fi->keep_cache = KEEP_CACHE_OPEN;

    e.ino = opargs.attr.st_ino;
    e.generation = 1;
    e.attr = opargs.attr;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;
    ret = reply_create(req, &e, fi);
    if (ret != 0) {
        if (ret == -ENOENT)
            interrupted = 1;
        goto err4;
    }

    return;

err4:
    do_queue_op(priv, &do_close, &opargs);
    dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop[1]);
err3:
    file_tab_put(priv->ftab, desc);
err2:
    free(ofile);
err1:
    if (!interrupted)
        reply_err(req, -ret);
}

/*
 * This function implements posix_fallocate() and equivalent fallocate() calls
 * only.
 */
static void
simplefs_fallocate(void *req, inum_t ino, int mode, off_t offset, off_t length,
                   struct file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = req_userdata(req);
    struct op_args opargs;

    /* VFS handles file descriptor access mode check on Linux */
    (void)fi;

    if (mode != 0) {
        ret = -EOPNOTSUPP;
        goto err;
    }
    if (offset < 0 || length <= 0) {
        ret = -EINVAL;
        goto err;
    }

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.op_data.rdwr_data.a_wr = null_data;
    opargs.op_data.rdwr_data.size = length;
    opargs.op_data.rdwr_data.off = offset;

    ret = do_queue_op(priv, &do_write_data, &opargs);
    if (ret != 0)
        goto err;

    ret = reply_err(req, 0);
    if (ret != 0 && ret != -ENOENT)
        goto err;

    return;

err:
    reply_err(req, -ret);
}

struct request_ops request_simplefs_ops = {
    .init_prepare   = &simplefs_init_prepare,
    .init           = &simplefs_init,
    .destroy_finish = &simplefs_destroy_finish,
    .lookup         = &simplefs_lookup,
    .forget         = &simplefs_forget,
    .getattr        = &simplefs_getattr,
    .setattr        = &simplefs_setattr,
    .readlink       = &simplefs_readlink,
    .mknod          = &simplefs_mknod,
    .mkdir          = &simplefs_mkdir,
    .unlink         = &simplefs_unlink,
    .rmdir          = &simplefs_rmdir,
    .symlink        = &simplefs_symlink,
    .rename         = &simplefs_rename,
    .link           = &simplefs_link,
    .open           = &simplefs_open,
    .read           = &simplefs_read,
    .write          = &simplefs_write,
    .flush          = &simplefs_flush,
    .release        = &simplefs_release,
    .fsync          = &simplefs_fsync,
    .opendir        = &simplefs_opendir,
    .readdir        = &simplefs_readdir,
    .releasedir     = &simplefs_releasedir,
    .fsyncdir       = &simplefs_fsyncdir,
    .statfs         = &simplefs_statfs,
    .setxattr       = &simplefs_setxattr,
    .getxattr       = &simplefs_getxattr,
    .listxattr      = &simplefs_listxattr,
    .removexattr    = &simplefs_removexattr,
    .access         = &simplefs_access,
    .create         = &simplefs_create,
    .fallocate      = &simplefs_fallocate
};

/* vi: set expandtab sw=4 ts=4: */
