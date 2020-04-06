/*
 * ops.c
 *
 * Note: All of the requests handled by simplefs are uninterruptible to simplify
 * error handling. Checks for the -ENOENT error return from fuse_reply_*() are
 * added for robustness, but this condition should never occur.
 */

#include "config.h"

#include "back_end.h"
#include "common.h"
#include "ops.h"
#include "simplefs.h"
#include "util.h"

#include <avl_tree.h>
#include <fifo.h>
#include <strings_ext.h>

#include <files/acc_ctl.h>

#include <myutil/version.h>

#include <fuse.h>
#include <fuse_lowlevel.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/param.h>
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
    fuse_ino_t  ino;
    uint64_t    nlink;
    uint64_t    refcnt;
    uint64_t    nlookup;
    int         nodelete;
};

enum db_obj_type {
    TYPE_HEADER = 1,
    TYPE_DIRENT,        /* look up by ino, name */
    TYPE_STAT,          /* look up by ino */
    TYPE_PAGE,          /* look up by ino, pgno */
    TYPE_XATTR          /* look up by ino, name */
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

struct db_obj_header {
    uint64_t    version;
    uint64_t    next_ino;
    uint8_t     reserved[112];
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

struct op_args {
    fuse_req_t              req;
    const struct fuse_ctx   *ctx;
    struct back_end         *be;
    struct ref_inodes       *ref_inodes;
    struct ref_ino          *refinop[4];
    fuse_ino_t              ino;
    struct db_key           k;
    struct db_obj_header    hdr;
    struct db_obj_stat      s;
    struct stat             attr;
    union {
        int                 inc_lookup_cnt; /* lookup() */
        uint64_t            nlookup;        /* forget() */
        int                 to_set;         /* setattr() */
        struct {
            fuse_ino_t      parent;
            const char      *name;
            dev_t           rdev;
            mode_t          mode;
            const char      *link;
        } mknod_data;                       /* create(), mkdir(), symlink(),
                                               mknod() */
        struct {
            fuse_ino_t      parent;
            const char      *name;
            fuse_ino_t      newparent;
            const char      *newname;
        } link_data;                        /* link(), rename(), unlink(),
                                               rmdir() */
        struct {
            off_t           off;
            size_t          size;
            char            *buf;
            struct iovec    *iov;
            int             count;
        } rdwr_data;                        /* read(), write(), readlink() */
        struct {
            struct open_dir *odir;
            off_t           off;
            char            *buf;
            size_t          bufsize;
            size_t          buflen;
        } readdir_data;                     /* readdir() */
        struct {
            const char      *name;
            char            *value;
            size_t          size;
            int             flags;
        } xattr_data;                       /* setxattr(), getxattr(),
                                               listxattr(), removexattr() */
        int                 mask;           /* access() */
    } op_data;
};

struct open_dir {
    char        cur_name[NAME_MAX+1];
    fuse_ino_t  ino;
};

struct open_file {
    fuse_ino_t ino;
};

struct free_ref_inodes_ctx {
    struct fspriv *priv;
    int err;
};

#define FSNAME PACKAGE_STRING
#define LIBNAME "libutil " LIBUTIL_VERSION

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

#ifndef HAVE_SYS_XATTR_H
#define XATTR_CREATE 1
#define XATTR_REPLACE 2
#endif

#define SIMPLEFS_MOUNT_PIPE_FD 4
#define SIMPLEFS_MOUNT_PIPE_MSG_OK "1"

#ifdef HAVE_STRUCT_STAT_ST_MTIMESPEC
#define st_atim st_atimespec
#define st_mtim st_mtimespec
#define st_ctim st_ctimespec
#endif

#define FMT_VERSION 2

#define DATA_BLOCK_MIN_SIZE 64
#define PG_SIZE (128 * 1024 - DATA_BLOCK_MIN_SIZE)

#define DB_PATHNAME "fs.db"

#define OP_RET_NONE INT_MAX

#define DB_OBJ_MAX_SIZE (sizeof(struct db_obj_stat))

#define NAME_CUR_DIR "."
#define NAME_PARENT_DIR ".."

#define CACHE_TIMEOUT 1800.0
#define KEEP_CACHE_OPEN 1

#ifndef OFF_MAX
#define OFF_MAX INT64_MAX
#endif

#define UNREF_MAX INT32_MAX

#define ROOT_DIR_INIT_PERMS (S_IRWXU)

#if 0 && !defined(NDEBUG)
#define DEBUG_DUMP
#endif

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static int init;

#define ASSERT_UNDER_TRANS(be) (assert(back_end_trans_new(be) == -EBUSY))

static void verror(int, const char *, va_list);

static int uint64_cmp(uint64_t, uint64_t);

static int db_key_cmp(const void *, const void *, struct back_end_key_ctx *);

static void *worker_td(void *);
static int do_queue_op(struct fspriv *, int (*)(void *), void *);
static int join_worker(struct fspriv *);

static void sync_cb(int, void *);

#ifdef DEBUG_DUMP
static int dump_cb(const void *, const void *, size_t, void *);
#endif
static int dump_db(struct back_end *);

static int ref_inode_cmp(const void *, const void *, void *);

static uint64_t adj_refcnt(uint64_t *, int32_t);
static int get_next_ino(struct back_end *, fuse_ino_t *);
static int unref_inode(struct back_end *, struct ref_inodes *, struct ref_ino *,
                       int32_t, int32_t, int32_t, int *);
static int free_ref_inodes_cb(const void *, void *);

static int inc_refcnt(struct back_end *, struct ref_inodes *, fuse_ino_t,
                      int32_t, int32_t, int32_t, struct ref_ino **);
static int dec_refcnt(struct ref_inodes *, int32_t, int32_t, int32_t,
                      struct ref_ino *);
static int set_ref_inode_nodelete(struct back_end *, struct ref_inodes *,
                                  fuse_ino_t, int);

static void do_set_ts(struct disk_timespec *, struct timespec *);
static void set_ts(struct disk_timespec *, struct disk_timespec *,
                   struct disk_timespec *);
static void deserialize_ts(struct timespec *, struct disk_timespec *);

static void deserialize_stat(struct stat *, struct db_obj_stat *);

static int add_xattr_name(char **, size_t *, size_t *, const char *);

static int truncate_file(struct back_end *, fuse_ino_t, off_t, off_t);
static int delete_file(struct back_end *, fuse_ino_t);

static void free_iov(struct iovec *, int);

static void abort_init(int, const char *, ...);

static int new_node(struct back_end *, struct ref_inodes *, fuse_ino_t,
                    const char *, uid_t, gid_t, mode_t, dev_t, off_t,
                    struct stat *, struct ref_ino **, int);

static int new_node_link(struct back_end *, struct ref_inodes *, fuse_ino_t,
                         fuse_ino_t, const char *, struct ref_ino **);
static int rem_node_link(struct back_end *, struct ref_inodes *, fuse_ino_t,
                         fuse_ino_t, const char *, int *, struct ref_ino **);

static int new_dir(struct back_end *, struct ref_inodes *, fuse_ino_t,
                   const char *, uid_t, gid_t, mode_t, struct stat *,
                   struct ref_ino **, int);
static int rem_dir(struct back_end *, struct ref_inodes *, fuse_ino_t,
                   fuse_ino_t, const char *, int, int);

static int new_dir_link(struct back_end *, struct ref_inodes *, fuse_ino_t,
                        fuse_ino_t, const char *, struct ref_ino **);
static int rem_dir_link(struct back_end *, struct ref_inodes *, fuse_ino_t,
                        fuse_ino_t, const char *, struct ref_ino **);

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
static int do_read(void *);
static int do_write(void *);
static int do_close(void *);
static int do_sync(void *);
static int do_read_header(void *);
static int do_setxattr(void *);
static int do_getxattr(void *);
static int do_listxattr(void *);
static int do_removexattr(void *);
static int do_access(void *);
static int do_create(void *);

static void simplefs_init(void *, struct fuse_conn_info *);
static void simplefs_destroy(void *);
static void simplefs_lookup(fuse_req_t, fuse_ino_t, const char *);
#if FUSE_USE_VERSION == 32
static void simplefs_forget(fuse_req_t, fuse_ino_t, uint64_t);
#else
static void simplefs_forget(fuse_req_t, fuse_ino_t, unsigned long);
#endif
static void simplefs_getattr(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void simplefs_setattr(fuse_req_t, fuse_ino_t, struct stat *, int,
                             struct fuse_file_info *);
static void simplefs_readlink(fuse_req_t, fuse_ino_t);
static void simplefs_mknod(fuse_req_t, fuse_ino_t, const char *, mode_t, dev_t);
static void simplefs_mkdir(fuse_req_t, fuse_ino_t, const char *, mode_t);
static void simplefs_unlink(fuse_req_t, fuse_ino_t, const char *);
static void simplefs_rmdir(fuse_req_t, fuse_ino_t, const char *);
static void simplefs_symlink(fuse_req_t, const char *, fuse_ino_t,
                             const char *);
#if FUSE_USE_VERSION == 32
static void simplefs_rename(fuse_req_t, fuse_ino_t, const char *, fuse_ino_t,
                            const char *, unsigned int);
#else
static void simplefs_rename(fuse_req_t, fuse_ino_t, const char *, fuse_ino_t,
                            const char *);
#endif
static void simplefs_link(fuse_req_t, fuse_ino_t, fuse_ino_t, const char *);
static void simplefs_open(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void simplefs_read(fuse_req_t, fuse_ino_t, size_t, off_t,
                          struct fuse_file_info *);
static void simplefs_write(fuse_req_t, fuse_ino_t, const char *, size_t, off_t,
                           struct fuse_file_info *);
static void simplefs_flush(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void simplefs_opendir(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void simplefs_readdir(fuse_req_t, fuse_ino_t, size_t, off_t,
                             struct fuse_file_info *);
static void simplefs_release(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void simplefs_fsync(fuse_req_t, fuse_ino_t, int,
                           struct fuse_file_info *);
static void simplefs_releasedir(fuse_req_t, fuse_ino_t,
                                struct fuse_file_info *);
static void simplefs_fsyncdir(fuse_req_t, fuse_ino_t, int,
                              struct fuse_file_info *);
static void simplefs_statfs(fuse_req_t, fuse_ino_t);
#ifdef __APPLE__
static void simplefs_setxattr(fuse_req_t, fuse_ino_t, const char *,
                              const char *, size_t, int, uint32_t);
static void simplefs_getxattr(fuse_req_t, fuse_ino_t, const char *, size_t,
                              uint32_t);
#else
static void simplefs_setxattr(fuse_req_t, fuse_ino_t, const char *,
                              const char *, size_t, int);
static void simplefs_getxattr(fuse_req_t, fuse_ino_t, const char *, size_t);
#endif
static void simplefs_listxattr(fuse_req_t, fuse_ino_t, size_t);
static void simplefs_removexattr(fuse_req_t, fuse_ino_t, const char *);
static void simplefs_access(fuse_req_t, fuse_ino_t, int);
static void simplefs_create(fuse_req_t, fuse_ino_t, const char *, mode_t,
                            struct fuse_file_info *);

static void
verror(int err, const char *fmt, va_list ap)
{
    char buf[128];

    vsnprintf(buf, sizeof(buf), fmt, ap);

    if (err) {
        int old_errno = errno;

        errno = (err < 0) ? -err : err;
        perror(buf);
        errno = old_errno;
    } else {
        fputs(buf, stderr);
        fputc('\n', stderr);
    }
}

static int
uint64_cmp(uint64_t n1, uint64_t n2)
{
    return (n1 > n2) - (n1 < n2);
}

static int
db_key_cmp(const void *k1, const void *k2, struct back_end_key_ctx *key_ctx)
{
    int cmp;
    struct db_key *key1 = (struct db_key *)k1;
    struct db_key *key2 = (struct db_key *)k2;

    if (key_ctx != NULL) {
        memcpy(key_ctx->last_key, k2, sizeof(struct db_key));
        key_ctx->last_key_valid = 1;
    }

    cmp = uint64_cmp(key1->type, key2->type);
    if ((cmp != 0) || (key1->type == TYPE_HEADER))
        return cmp;

    cmp = uint64_cmp(key1->ino, key2->ino);
    if (cmp != 0)
        return cmp;

    switch (key1->type) {
    case TYPE_DIRENT:
    case TYPE_XATTR:
        cmp = strcmp(key1->name, key2->name);
        break;
    case TYPE_PAGE:
        cmp = uint64_cmp(key1->pgno, key2->pgno);
    case TYPE_STAT:
        break;
    default:
        abort();
    }

    return cmp;
}

static void *
worker_td(void *args)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = (struct mount_data *)args;
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

        ret = (*(op->op))(op->args);

        pthread_mutex_lock(&op->mtx);
        op->ret = ret;
        pthread_cond_broadcast(&op->cv);
        pthread_mutex_unlock(&op->mtx);
    }

    return (void *)(intptr_t)ret;
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
    void *retval;

    op.op = NULL;
    opp = &op;
    err = fifo_put(priv->queue, &opp);
    if (err)
        return err;

    err = -pthread_join(priv->worker_td, &retval);

    return err ? err : (intptr_t)retval;
}

static void
sync_cb(int status, void *ctx)
{
    struct fspriv *priv = (struct fspriv *)ctx;

    if (status < 0)
        priv->wb_err = status;
}

#ifdef DEBUG_DUMP
static int
dump_cb(const void *key, const void *data, size_t datasize, void *ctx)
{
    struct db_key *k = (struct db_key *)key;
    struct db_obj_dirent *de;
    struct db_obj_header *hdr;
    struct db_obj_stat *s;

    (void)ctx;

    switch (k->type) {
    case TYPE_HEADER:
        assert(datasize == sizeof(*hdr));
        hdr = (struct db_obj_header *)data;

        fprintf(stderr, "Header: next_ino %" PRIu64 "\n", hdr->next_ino);
        break;
    case TYPE_DIRENT:
        assert(datasize == sizeof(*de));
        de = (struct db_obj_dirent *)data;

        fprintf(stderr, "Directory entry: directory %" PRIu64 ", name %s -> "
                        "node %" PRIu64 "\n",
                (uint64_t)(k->ino), k->name, (uint64_t)(de->ino));
        break;
    case TYPE_STAT:
        assert(datasize == sizeof(*s));
        s = (struct db_obj_stat *)data;

        fprintf(stderr, "I-node entry: node %" PRIu64 " -> st_ino %" PRIu64
                        "\n",
                (uint64_t)(k->ino), (uint64_t)(s->st_ino));
        break;
    case TYPE_PAGE:
        fprintf(stderr, "Page: node %" PRIu64 ", page %" PRIu64 ", size %zu\n",
                (uint64_t)(k->ino), (uint64_t)(k->pgno), datasize);
        break;
    case TYPE_XATTR:
        fprintf(stderr, "Extended attribute entry: node %" PRIu64 ", name %s, "
                        "size %zu\n",
                (uint64_t)(k->ino), k->name, datasize);
        break;
    default:
        abort();
    }

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
    struct ref_ino *ino1 = *(struct ref_ino **)k1;
    struct ref_ino *ino2 = *(struct ref_ino **)k2;

    (void)ctx;

    return uint64_cmp(ino1->ino, ino2->ino);
}

static uint64_t
adj_refcnt(uint64_t *refcnt, int32_t delta)
{
    if (delta != 0)
        *refcnt = (delta == -INT_MAX) ? 0 : (*refcnt + delta);

    return *refcnt;
}

/*
 * FIXME: Revise this function to use disk addresses as I-node numbers once
 * reaching ULONG_MAX, instead of returning -ENOSPC
 */
static int
get_next_ino(struct back_end *be, fuse_ino_t *ino)
{
    fuse_ino_t ret;
    int res;
    struct db_key k;
    struct db_obj_header hdr;

    k.type = TYPE_HEADER;
    res = back_end_look_up(be, &k, NULL, &hdr, NULL, 0);
    if (res != 1)
        return (res == 0) ? -EILSEQ : res;

    if (hdr.next_ino == ULONG_MAX)
        return -ENOSPC;
    ret = (hdr.next_ino)++;

    res = back_end_replace(be, &k, &hdr, sizeof(hdr));
    if (res != 0)
        return res;

    *ino = ret;
    return 0;
}

/*
 * This function must be called under a transaction to allow cancelling changes
 * in case of an error, unless nlink is 0.
 */
static int
unref_inode(struct back_end *be, struct ref_inodes *ref_inodes,
            struct ref_ino *ino, int32_t nlink, int32_t nref, int32_t nlookup,
            int *deleted)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    uint64_t nlinkp, refcntp, nlookupp;

    if (nlink != 0) {
        k.type = TYPE_STAT;
        k.ino = ino->ino;
        ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
        if (ret != 1)
            return (ret == 0) ? -ENOENT : ret;
    }

    pthread_mutex_lock(&ref_inodes->ref_inodes_mtx);
    nlinkp = adj_refcnt(&ino->nlink, nlink);
    refcntp = adj_refcnt(&ino->refcnt, nref);
    nlookupp = adj_refcnt(&ino->nlookup, nlookup);
    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);

    if ((nlinkp == 0) && (refcntp == 0) && (nlookupp == 0)) {
        ret = delete_file(be, ino->ino);
        if ((ret == 0) && (deleted != NULL))
            *deleted = 1;
        return ret;
    }

    if (nlink != 0) {
        ASSERT_UNDER_TRANS(be);

        s.st_nlink = (uint32_t)nlinkp;
        assert(s.st_ino == k.ino);
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
    struct free_ref_inodes_ctx *fctx = (struct free_ref_inodes_ctx *)ctx;
    struct fspriv *priv = fctx->priv;
    struct ref_ino *ino = *(struct ref_ino **)keyval;

    err = unref_inode(priv->be, &priv->ref_inodes, ino, 0, -INT_MAX, -INT_MAX,
                      NULL);
    if (err)
        fctx->err = err;

    free(ino);

    return 0;
}

static int
inc_refcnt(struct back_end *be, struct ref_inodes *ref_inodes, fuse_ino_t ino,
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

        refinop = do_malloc(sizeof(*refinop));
        if (refinop == NULL) {
            ret = MINUS_ERRNO;
            goto err1;
        }

        k.type = TYPE_STAT;
        k.ino = ino;
        ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
        if (ret != 1) {
            if (ret == 0)
                ret = -ENOENT;
            goto err2;
        }

        refinop->ino = ino;
        refinop->nlink = s.st_nlink;
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

    if (!(inop->nodelete) && (inop->nlink == 0) && (inop->refcnt == 0)
        && (inop->nlookup == 0)) {
        err = avl_tree_delete(ref_inodes->ref_inodes, &inop);
        if (!err)
            free(inop);
    }

    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);

    return err;
}

static int
set_ref_inode_nodelete(struct back_end *be, struct ref_inodes *ref_inodes,
                       fuse_ino_t ino, int nodelete)
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

    if (!nodelete && (nlink == 0) && (refcnt == 0) && (nlookup == 0))
        return delete_file(be, ino);

    return 0;

err:
    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);
    return ret;
}

static void
do_set_ts(struct disk_timespec *ts, struct timespec *srcts)
{
    struct timespec timespec;

    if (srcts == NULL) {
        srcts = &timespec;
        if (clock_gettime(CLOCK_REALTIME, srcts) != 0) {
            memset(ts, 0, sizeof(*ts));
            return;
        }
    }

    ts->tv_sec = srcts->tv_sec;
    ts->tv_nsec = srcts->tv_nsec;
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
deserialize_ts(struct timespec *ts, struct disk_timespec *disk_ts)
{
    ts->tv_sec = disk_ts->tv_sec;
    ts->tv_nsec = disk_ts->tv_nsec;
}

static void
deserialize_stat(struct stat *s, struct db_obj_stat *ds)
{
    s->st_dev = ds->st_dev;
    s->st_ino = ds->st_ino;
    s->st_mode = ds->st_mode;
    s->st_nlink = ds->st_nlink;
    s->st_uid = ds->st_uid;
    s->st_gid = ds->st_gid;
    s->st_rdev = ds->st_rdev;
    s->st_size = ds->st_size;
    s->st_blksize = ds->st_blksize;
    s->st_blocks = ds->st_blocks;
    deserialize_ts(&s->st_atim, &ds->st_atim);
    deserialize_ts(&s->st_mtim, &ds->st_mtim);
    deserialize_ts(&s->st_ctim, &ds->st_ctim);
}

static int
add_xattr_name(char **names, size_t *len, size_t *size, const char *name)
{
    size_t namelen = strlen(name) + 1;

    if (*len + namelen > *size) {
        char *tmp;
        size_t newsize = (*len + namelen) * 2;

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
truncate_file(struct back_end *be, fuse_ino_t ino, off_t oldsize, off_t newsize)
{
    int ret;
    size_t lastpgsz;
    struct db_key k;
    uint64_t i;
    uint64_t newnumpg, oldnumpg;

    ASSERT_UNDER_TRANS(be);

    if (newsize >= oldsize)
        return 0;

    oldnumpg = (oldsize + PG_SIZE - 1) / PG_SIZE;
    newnumpg = (newsize + PG_SIZE - 1) / PG_SIZE;

    k.type = TYPE_PAGE;
    k.ino = ino;

    for (i = oldnumpg - 1;; i--) {
        k.pgno = i;

        ret = back_end_delete(be, &k);
        if (ret != 0)
            return ret;

        if (i == newnumpg)
            break;
    }

    if ((newnumpg > 0) && (lastpgsz = newsize % PG_SIZE) > 0) {
        char buf[PG_SIZE];

        k.pgno = newnumpg - 1;

        ret = back_end_look_up(be, &k, NULL, buf, NULL, 0);
        if (ret != 1)
            return (ret == 0) ? -ENOENT : ret;

        return back_end_replace(be, &k, buf, lastpgsz);
    }

    return 0;
}

static int
delete_file(struct back_end *be, fuse_ino_t ino)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;

    k.type = TYPE_STAT;
    k.ino = ino;

    ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    if (S_ISREG(s.st_mode)) {
        uint64_t i, numpg;

        numpg = (s.st_size + PG_SIZE - 1) / PG_SIZE;

        k.type = TYPE_PAGE;

        i = numpg;
        while (i > 0) {
            k.pgno = --i;

            ret = back_end_delete(be, &k);
            if (ret != 0)
                return ret;
        }
    }

    k.type = TYPE_STAT;

    return back_end_delete(be, &k);
}

static void
free_iov(struct iovec *iov, int count)
{
    int i;

    for (i = 0; i < count; i++)
        free(iov[i].iov_base);
}

static void
abort_init(int err, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    verror(err, fmt, ap);
    va_end(ap);

    simplefs_exit();
}

/*
 * Side effects:
 * - Sets link count of new node to 1
 * - Sets lookup count of new node to 1
 */
static int
new_node(struct back_end *be, struct ref_inodes *ref_inodes, fuse_ino_t parent,
         const char *name, uid_t uid, gid_t gid, mode_t mode, dev_t rdev,
         off_t size, struct stat *attr, struct ref_ino **inop, int notrans)
{
    fuse_ino_t ino;
    int ret;
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

    ret = get_next_ino(be, &ino);
    if (ret != 0)
        goto err1;

    k.type = TYPE_STAT;
    k.ino = ino;

    s.st_dev = 64 * 1024;
    s.st_ino = ino;
    s.st_mode = mode & (S_IFMT | ALLPERMS);
    s.st_nlink = 0;
    s.st_uid = uid;
    s.st_gid = gid;
    s.st_rdev = rdev;
    s.st_size = size;
    s.st_blksize = PG_SIZE;
    s.st_blocks = 0;
    set_ts(&s.st_atim, &s.st_mtim, &s.st_ctim);
    s.num_ents = 0;

    ret = back_end_insert(be, &k, &s, sizeof(s));
    if (ret != 0)
        goto err1;

    ret = new_node_link(be, ref_inodes, ino, parent, name, &refinop[0]);
    if (ret != 0)
        goto err1;

    ret = inc_refcnt(be, ref_inodes, ino, 0, 0, 1, &refinop[1]);
    if (ret != 0)
        goto err2;

    k.ino = parent;

    ret = back_end_look_up(be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err3;
    }

    ++(ps.num_ents);

    assert(ps.st_ino == k.ino);
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
    memcpy(inop, refinop, 2 * sizeof(struct ref_ino *));

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
new_node_link(struct back_end *be, struct ref_inodes *ref_inodes,
              fuse_ino_t ino, fuse_ino_t newparent, const char *newname,
              struct ref_ino **inop)
{
    int ret;
    struct db_key k;
    struct db_obj_dirent de;
    struct db_obj_stat s;
    struct ref_ino *refinop;

    ASSERT_UNDER_TRANS(be);

    k.type = TYPE_DIRENT;
    k.ino = newparent;
    strlcpy(k.name, newname, sizeof(k.name));

    de.ino = ino;

    ret = back_end_insert(be, &k, &de, sizeof(de));
    if (ret != 0)
        return ret;

    k.type = TYPE_STAT;
    k.ino = ino;

    ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    ++(s.st_nlink);

    assert(s.st_ino == k.ino);
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
new_dir(struct back_end *be, struct ref_inodes *ref_inodes, fuse_ino_t parent,
        const char *name, uid_t uid, gid_t gid, mode_t mode, struct stat *attr,
        struct ref_ino **inop, int notrans)
{
    fuse_ino_t ino;
    int ret;
    int rootdir = (parent == 0);
    struct db_key k;
    struct db_obj_stat s;
    struct ref_ino *refinop[4];

    if (!notrans) {
        ret = back_end_trans_new(be);
        if (ret != 0)
            return ret;
    }

    if (rootdir)
        parent = ino = FUSE_ROOT_ID;
    else {
        ret = get_next_ino(be, &ino);
        if (ret != 0)
            goto err1;
    }

    k.type = TYPE_STAT;
    k.ino = ino;

    s.st_dev = 64 * 1024;
    s.st_ino = ino;
    s.st_mode = S_IFDIR | (mode & ALLPERMS);
    s.st_nlink = 0;
    s.st_uid = uid;
    s.st_gid = gid;
    s.st_rdev = 0;
    s.st_size = 0;
    s.st_blksize = PG_SIZE;
    s.st_blocks = 0;
    set_ts(&s.st_atim, &s.st_mtim, &s.st_ctim);
    s.num_ents = 0;

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

        k.ino = parent;

        ret = back_end_look_up(be, &k, NULL, &ps, NULL, 0);
        if (ret != 1) {
            if (ret == 0)
                ret = -ENOENT;
            goto err5;
        }

        ++(ps.num_ents);

        assert(ps.st_ino == k.ino);
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
    memcpy(inop, refinop, 4 * sizeof(struct ref_ino *));

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
rem_dir(struct back_end *be, struct ref_inodes *ref_inodes, fuse_ino_t ino,
        fuse_ino_t parent, const char *name, int notrans, int nodelete)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct ref_ino *refinop[3];

    k.type = TYPE_STAT;
    k.ino = ino;
    ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;
    if (s.num_ents != 0)
        return -ENOTEMPTY;

    k.ino = parent;
    ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    if (!nodelete) {
        ret = set_ref_inode_nodelete(be, ref_inodes, ino, 1);
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

    ret = rem_dir_link(be, ref_inodes, ino, parent, name, &refinop[0]);
    if (ret != 0)
        goto err2;

    ret = rem_dir_link(be, ref_inodes, parent, ino, NAME_PARENT_DIR,
                       &refinop[1]);
    if (ret != 0)
        goto err3;
    ret = rem_dir_link(be, ref_inodes, ino, ino, NAME_CUR_DIR, &refinop[2]);
    if (ret != 0)
        goto err4;

    --(s.num_ents);
    ret = back_end_replace(be, &k, &s, sizeof(s));
    if (ret != 0)
        goto err5;

    if (!notrans) {
        ret = back_end_trans_commit(be);
        if (ret != 0)
            goto err5;
    }

    if (!nodelete)
        set_ref_inode_nodelete(be, ref_inodes, ino, 0);

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
        set_ref_inode_nodelete(be, ref_inodes, ino, 0);
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
new_dir_link(struct back_end *be, struct ref_inodes *ref_inodes, fuse_ino_t ino,
             fuse_ino_t newparent, const char *newname, struct ref_ino **inop)
{
    int ret;
    struct db_key k;
    struct db_obj_dirent de;
    struct db_obj_stat s;
    struct ref_ino *refinop;

    ASSERT_UNDER_TRANS(be);

    k.type = TYPE_DIRENT;
    k.ino = newparent;
    strlcpy(k.name, newname, sizeof(k.name));

    de.ino = ino;

    ret = back_end_insert(be, &k, &de, sizeof(de));
    if (ret != 0)
        return ret;

    k.type = TYPE_STAT;
    k.ino = ino;

    ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    ++(s.st_nlink);

    assert(s.st_ino == k.ino);
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
rem_node_link(struct back_end *be, struct ref_inodes *ref_inodes,
              fuse_ino_t ino, fuse_ino_t parent, const char *name, int *deleted,
              struct ref_ino **inop)
{
    int ret;
    struct db_key k;
    struct ref_ino refino, *refinop;

    ASSERT_UNDER_TRANS(be);

    k.type = TYPE_DIRENT;
    k.ino = parent;
    strlcpy(k.name, name, sizeof(k.name));

    ret = back_end_delete(be, &k);
    if (ret != 0)
        return ret;

    refino.ino = ino;
    refinop = &refino;

    pthread_mutex_lock(&ref_inodes->ref_inodes_mtx);
    ret = avl_tree_search(ref_inodes->ref_inodes, &refinop, &refinop);
    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    ret = unref_inode(be, ref_inodes, refinop, -1, 0, 0, deleted);
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
rem_dir_link(struct back_end *be, struct ref_inodes *ref_inodes, fuse_ino_t ino,
             fuse_ino_t parent, const char *name, struct ref_ino **inop)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct ref_ino refino, *refinop;

    ASSERT_UNDER_TRANS(be);

    k.type = TYPE_DIRENT;
    k.ino = parent;
    strlcpy(k.name, name, sizeof(k.name));

    ret = back_end_delete(be, &k);
    if (ret != 0)
        return ret;

    k.type = TYPE_STAT;
    k.ino = ino;

    ret = back_end_look_up(be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    refino.ino = ino;
    refinop = &refino;

    pthread_mutex_lock(&ref_inodes->ref_inodes_mtx);
    ret = avl_tree_search(ref_inodes->ref_inodes, &refinop, &refinop);
    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    --(s.st_nlink);
    ret = unref_inode(be, ref_inodes, refinop, -1, 0, 0, NULL);
    if (ret == 0)
        *inop = refinop;

    return ret;
}

static int
do_look_up(void *args)
{
    int ret;
    struct db_key k;
    struct db_obj_dirent de;
    struct op_args *opargs = (struct op_args *)args;

    switch (opargs->k.type) {
    case TYPE_DIRENT:
        ret = back_end_look_up(opargs->be, &opargs->k, NULL, &de, NULL, 0);
        if (ret != 1)
            return ret;

        k.type = TYPE_STAT;
        k.ino = de.ino;
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
        ret = inc_refcnt(opargs->be, opargs->ref_inodes, opargs->s.st_ino, 0,
                         0, 1, opargs->refinop);
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
    struct op_args *opargs = (struct op_args *)args;

    k.type = TYPE_STAT;
    k.ino = opargs->ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    to_set = opargs->op_data.to_set;
    trunc = !!(to_set & FUSE_SET_ATTR_SIZE);

    if (trunc) {
        if (!S_ISREG(s.st_mode))
            return -EINVAL;

        ret = back_end_trans_new(opargs->be);
        if (ret != 0)
            return ret;

        ret = truncate_file(opargs->be, opargs->ino, s.st_size,
                            opargs->attr.st_size);
        if (ret != 0)
            goto err;
        s.st_size = opargs->attr.st_size;
    }

    if (to_set & FUSE_SET_ATTR_MODE)
        s.st_mode = (s.st_mode & ~ALLPERMS) | (opargs->attr.st_mode & ALLPERMS);

    if (to_set & FUSE_SET_ATTR_UID)
        s.st_uid = opargs->attr.st_uid;
    if (to_set & FUSE_SET_ATTR_GID)
        s.st_gid = opargs->attr.st_gid;

    if ((to_set & (FUSE_SET_ATTR_MTIME_NOW | FUSE_SET_ATTR_MTIME)) == 0) {
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
            do_set_ts(&s.st_mtim, NULL);
    } else {
        if (to_set & FUSE_SET_ATTR_MTIME_NOW)
            do_set_ts(&s.st_mtim, NULL);
        if (to_set & FUSE_SET_ATTR_MTIME)
            do_set_ts(&s.st_mtim, &opargs->attr.st_mtim);
    }

    if (to_set & FUSE_SET_ATTR_ATIME_NOW)
        do_set_ts(&s.st_atim, NULL);
    if (to_set & FUSE_SET_ATTR_ATIME)
        do_set_ts(&s.st_atim, &opargs->attr.st_atim);

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
    do_set_ts(&s.st_ctim, NULL);

    ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
    if (ret != 0) {
        if (trunc)
            goto err;
        return ret;
    }

    if (trunc) {
        ret = back_end_trans_commit(opargs->be);
        if (ret != 0)
            goto err;
    }

    deserialize_stat(&opargs->attr, &s);
    if (S_ISDIR(opargs->attr.st_mode))
        opargs->attr.st_size = s.num_ents;

    return 0;

err:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_read_symlink(void *args)
{
    const char *link;
    int ret;
    size_t buflen;
    struct db_key k;
    struct op_args *opargs = (struct op_args *)args;

    k.type = TYPE_PAGE;
    k.ino = opargs->ino;
    k.pgno = 0;

    ret = back_end_look_up(opargs->be, &k, NULL, NULL, &buflen, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    link = do_malloc(buflen);
    if (link == NULL)
        return MINUS_ERRNO;

    ret = back_end_look_up(opargs->be, &k, NULL, (void *)link, NULL, 0);
    if (ret != 1) {
        free((void *)link);
        return (ret == 0) ? -ENOENT : ret;
    }

    opargs->op_data.rdwr_data.buf = (char *)link;

    return 0;
}

static int
do_forget(void *args)
{
    int ret;
    struct op_args *opargs = (struct op_args *)args;
    struct ref_ino refino, *refinop;
    uint64_t to_unref, unref;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    refino.ino = opargs->ino;
    refinop = &refino;

    pthread_mutex_lock(&opargs->ref_inodes->ref_inodes_mtx);
    ret = avl_tree_search(opargs->ref_inodes->ref_inodes, &refinop, &refinop);
    pthread_mutex_unlock(&opargs->ref_inodes->ref_inodes_mtx);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err;
    }

    for (to_unref = opargs->op_data.nlookup; to_unref > 0; to_unref -= unref) {
        unref = MIN(UNREF_MAX, to_unref);

        ret = unref_inode(opargs->be, opargs->ref_inodes, refinop, 0, 0,
                          -(int32_t)unref, NULL);
        if (ret != 0)
            goto err;
    }

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err;

    pthread_mutex_lock(&opargs->ref_inodes->ref_inodes_mtx);
    if (!(refinop->nodelete) && (refinop->nlink == 0) && (refinop->refcnt == 0)
        && (refinop->nlookup == 0)) {
        if (avl_tree_delete(opargs->ref_inodes->ref_inodes, &refinop) == 0)
            free(refinop);
    }
    pthread_mutex_unlock(&opargs->ref_inodes->ref_inodes_mtx);

    return 0;

err:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_create_node(void *args)
{
    const struct fuse_ctx *ctx;
    int mode;
    int ret;
    struct db_key k;
    struct db_obj_stat ps;
    struct op_args *opargs = (struct op_args *)args;

    ctx = opargs->ctx;

    mode = opargs->op_data.mknod_data.mode;

    if (((mode & S_IFMT) == S_IFDIR) || ((mode & S_IFMT) == S_IFLNK))
        return -EINVAL;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

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
                   mode & ~(ctx->umask), opargs->op_data.mknod_data.rdev, 0,
                   &opargs->attr, opargs->refinop, 1);
    if (ret != 0)
        goto err1;

    k.type = TYPE_STAT;
    k.ino = opargs->ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err2;
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
    set_ts(NULL, &ps.st_mtim, &ps.st_ctim);

    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err2;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err2;

    dump_db(opargs->be);

    return 0;

err2:
    dec_refcnt(opargs->ref_inodes, 0, 0, -1, opargs->refinop[1]);
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, opargs->refinop[0]);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_create_dir(void *args)
{
    const struct fuse_ctx *ctx;
    int ret;
    int rootdir;
    struct db_key k;
    struct db_obj_stat ps;
    struct op_args *opargs = (struct op_args *)args;

    ctx = opargs->ctx;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    /* POSIX-1.2008, mkdir, para. 6:
     * Upon successful completion, mkdir() shall mark for update the last data
     * access, last data modification, and last file status change timestamps of
     * the directory. */
    ret = new_dir(opargs->be, opargs->ref_inodes, opargs->ino,
                  opargs->op_data.mknod_data.name, ctx->uid, ctx->gid,
                  opargs->op_data.mknod_data.mode & ~(ctx->umask),
                  &opargs->attr, opargs->refinop, 1);
    if (ret != 0)
        goto err1;

    rootdir = (opargs->ino == 0);

    k.type = TYPE_STAT;
    k.ino = opargs->ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err2;
    }

    /* ", mkdir, para. 6:
     * Also, the last data modification and last file status change timestamps
     * of the directory that contains the new entry shall be marked for
     * update. */
    set_ts(NULL, &ps.st_mtim, &ps.st_ctim);

    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err2;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err2;

    dump_db(opargs->be);

    return 0;

err2:
    dec_refcnt(opargs->ref_inodes, 0, 0, -1, opargs->refinop[3]);
    if (!rootdir)
        dec_refcnt(opargs->ref_inodes, -1, 0, 0, opargs->refinop[2]);
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, opargs->refinop[1]);
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, opargs->refinop[0]);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_remove_node_link(void *args)
{
    const char *name;
    fuse_ino_t parent;
    int deleted;
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = (struct op_args *)args;
    struct ref_ino *refinop;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    parent = opargs->op_data.link_data.parent;
    name = opargs->op_data.link_data.name;

    k.type = TYPE_STAT;
    k.ino = parent;

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err1;
    }

    ret = set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, opargs->ino,
                                 1);
    if (ret != 0)
        goto err1;

    ret = rem_node_link(opargs->be, opargs->ref_inodes, opargs->ino, parent,
                        name, &deleted, &refinop);
    if (ret != 0)
        goto err2;

    /* POSIX-1.2008, unlink, para. 4:
     * Upon successful completion, unlink() shall mark for update the last data
     * modification and last file status change timestamps of the parent
     * directory. */
    set_ts(NULL, &s.st_mtim, &s.st_ctim);
    --(s.num_ents);

    ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
    if (ret != 0)
        goto err3;

    if (!deleted) {
        k.ino = opargs->ino;

        ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
        if (ret != 1) {
            if (ret == 0)
                ret = -ENOENT;
            goto err3;
        }

        /* ", unlink, para. 4:
         * Also, if the file's link count is not 0, the last file status change
         * timestamp of the file shall be marked for update. */
        do_set_ts(&s.st_ctim, NULL);

        ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
        if (ret != 0)
            goto err3;
    }

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err3;

    set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, opargs->ino, 0);

    dump_db(opargs->be);

    return 0;

err3:
    inc_refcnt(opargs->be, opargs->ref_inodes, opargs->ino, 1, 0, 0, &refinop);
err2:
    set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, opargs->ino, 0);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_remove_dir(void *args)
{
    const char *name;
    fuse_ino_t parent;
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = (struct op_args *)args;

    k.type = TYPE_STAT;
    k.ino = opargs->ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;
    if (s.num_ents != 0)
        return -ENOTEMPTY;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    parent = opargs->op_data.link_data.parent;
    name = opargs->op_data.link_data.name;

    ret = set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, opargs->ino,
                                 1);
    if (ret != 0)
        goto err1;

    ret = rem_dir(opargs->be, opargs->ref_inodes, opargs->ino, parent, name, 1,
                  1);
    if (ret != 0)
        goto err2;

    k.ino = parent;

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err3;
    }

    /* POSIX-1.2008, rmdir, para. 7:
     * Upon successful completion, rmdir() shall mark for update the last data
     * modification and last file status change timestamps of the parent
     * directory. */
    set_ts(NULL, &s.st_mtim, &s.st_ctim);

    ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
    if (ret != 0)
        goto err3;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err3;

    set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, opargs->ino, 0);

    dump_db(opargs->be);

    return 0;

err3:
    inc_refcnt(opargs->be, opargs->ref_inodes, opargs->ino, 2, 0, 0,
               opargs->refinop);
    inc_refcnt(opargs->be, opargs->ref_inodes, parent, 1, 0, 0,
               opargs->refinop);
err2:
    set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, opargs->ino, 0);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_create_symlink(void *args)
{
    const char *link, *name;
    const struct fuse_ctx *ctx;
    fuse_ino_t parent;
    int ret;
    size_t len;
    struct db_key k;
    struct db_obj_stat ps;
    struct op_args *opargs = (struct op_args *)args;

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

    /* POSIX-1.2008, symlink, para. 7:
     * Upon successful completion, symlink() shall mark for update the last data
     * access, last data modification, and last file status change timestamps of
     * the symbolic link. */
    ret = new_node(opargs->be, opargs->ref_inodes, parent, name, ctx->uid,
                   ctx->gid, S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO, 0,
                   (off_t)len, &opargs->attr, opargs->refinop, 1);
    if (ret != 0)
        goto err1;

    k.type = TYPE_PAGE;
    k.ino = opargs->attr.st_ino;
    k.pgno = 0;

    ret = back_end_insert(opargs->be, &k, link, len + 1);
    if (ret != 0)
        goto err2;

    k.type = TYPE_STAT;
    k.ino = parent;

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err2;
    }

    /* ", symlink, para. 7:
     * Also, the last data modification and last file status change timestamps
     * of the directory that contains the new entry shall be marked for
     * update. */
    set_ts(NULL, &ps.st_mtim, &ps.st_ctim);

    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err2;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err2;

    dump_db(opargs->be);

    return 0;

err2:
    dec_refcnt(opargs->ref_inodes, 0, 0, -1, opargs->refinop[1]);
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, opargs->refinop[0]);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_rename(void *args)
{
    const char *name, *newname;
    fuse_ino_t parent, newparent;
    int existing, ret;
    struct db_key k;
    struct db_obj_dirent dde, sde;
    struct db_obj_stat ds, ps, ss;
    struct op_args *opargs = (struct op_args *)args;
    struct ref_ino *refinop[3];

    parent = opargs->op_data.link_data.parent;
    name = opargs->op_data.link_data.name;
    newparent = opargs->op_data.link_data.newparent;
    newname = opargs->op_data.link_data.newname;

    k.type = TYPE_DIRENT;
    k.ino = parent;
    strlcpy(k.name, name, sizeof(k.name));

    ret = back_end_look_up(opargs->be, &k, NULL, &sde, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    k.type = TYPE_STAT;
    k.ino = sde.ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &ss, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, ss.st_ino, 1);
    if (ret != 0)
        goto err1;

    k.type = TYPE_DIRENT;
    k.ino = newparent;
    strlcpy(k.name, newname, sizeof(k.name));

    ret = back_end_look_up(opargs->be, &k, NULL, &dde, NULL, 0);
    if (ret != 0) {
        if (ret != 1)
            goto err2;

        k.type = TYPE_STAT;
        k.ino = dde.ino;

        ret = back_end_look_up(opargs->be, &k, NULL, &ds, NULL, 0);
        if (ret != 1) {
            if (ret == 0)
                ret = -ENOENT;
            goto err2;
        }

        /* delete existing link or directory */

        if (!S_ISDIR(ss.st_mode) && S_ISDIR(ds.st_mode)) {
            ret = -EISDIR;
            goto err2;
        }
        if (S_ISDIR(ss.st_mode) && !S_ISDIR(ds.st_mode)) {
            ret = -ENOTDIR;
            goto err2;
        }

        ret = set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, ds.st_ino,
                                     1);
        if (ret != 0)
            goto err2;

        if (S_ISDIR(ds.st_mode)) {
            ret = rem_dir(opargs->be, opargs->ref_inodes, ds.st_ino, newparent,
                          newname, 1, 1);
        } else {
            ret = rem_node_link(opargs->be, opargs->ref_inodes, ds.st_ino,
                                newparent, newname, NULL, &refinop[0]);
        }
        if (ret != 0) {
            set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, ds.st_ino,
                                   0);
            goto err2;
        }

        existing = 1;
    } else
        existing = 0;

    k.type = TYPE_STAT;

    if (S_ISDIR(ss.st_mode)) {
        ret = new_dir_link(opargs->be, opargs->ref_inodes, ss.st_ino, newparent,
                           newname, &refinop[1]);
        if (ret != 0)
            goto err3;

        ret = rem_dir_link(opargs->be, opargs->ref_inodes, ss.st_ino, parent,
                           name, &refinop[2]);
    } else {
        ret = new_node_link(opargs->be, opargs->ref_inodes, ss.st_ino,
                            newparent, newname, &refinop[1]);
        if (ret != 0)
            goto err3;

        ret = rem_node_link(opargs->be, opargs->ref_inodes, ss.st_ino, parent,
                            name, NULL, &refinop[2]);
    }
    if (ret != 0)
        goto err4;

    k.ino = newparent;

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err5;
    }

    /* POSIX-1.2008, rename, para. 10:
     * Upon successful completion, rename() shall mark for update the last data
     * modification and last file status change timestamps of the parent
     * directory of each file. */
    set_ts(NULL, &ps.st_mtim, &ps.st_ctim);
    if (!existing)
        ++(ps.num_ents);

    assert(ps.st_ino == k.ino);
    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err5;

    k.ino = parent;

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err5;
    }

    /* ", rename, para. 10:
     * " */
    set_ts(NULL, &ps.st_mtim, &ps.st_ctim);
    --(ps.num_ents);

    assert(ps.st_ino == k.ino);
    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err5;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err5;

    set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, ds.st_ino, 0);
    set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, ss.st_ino, 0);

    return 0;

err5:
    inc_refcnt(opargs->be, opargs->ref_inodes, ss.st_ino, 1, 0, 0, refinop);
err4:
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, refinop[1]);
err3:
    if (existing) {
        if (S_ISDIR(ds.st_mode)) {
            inc_refcnt(opargs->be, opargs->ref_inodes, ds.st_ino, 2, 0, 0,
                       refinop);
            inc_refcnt(opargs->be, opargs->ref_inodes, newparent, 1, 0, 0,
                       refinop);
        } else {
            inc_refcnt(opargs->be, opargs->ref_inodes, ds.st_ino, 1, 0, 0,
                       refinop);
        }
        set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, ds.st_ino, 0);
    }
err2:
    set_ref_inode_nodelete(opargs->be, opargs->ref_inodes, ss.st_ino, 0);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_create_node_link(void *args)
{
    const char *newname;
    fuse_ino_t newparent;
    int ret;
    struct db_key k;
    struct db_obj_stat ps;
    struct op_args *opargs = (struct op_args *)args;
    struct ref_ino *refinop;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    newparent = opargs->op_data.link_data.newparent;
    newname = opargs->op_data.link_data.newname;

    ret = new_node_link(opargs->be, opargs->ref_inodes, opargs->ino, newparent,
                        newname, &refinop);
    if (ret != 0)
        goto err1;

    k.type = TYPE_STAT;
    k.ino = opargs->ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &opargs->s, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err2;
    }

    /* POSIX-1.2008, link, para. 5:
     * Upon successful completion, link() shall mark for update the last file
     * status change timestamp of the file. */
    do_set_ts(&opargs->s.st_ctim, NULL);

    ret = back_end_replace(opargs->be, &k, &opargs->s, sizeof(opargs->s));
    if (ret != 0)
        goto err2;

    k.ino = newparent;

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err2;
    }

    /* ", link, para. 5:
     * Also, the last data modification and last file status change timestamps
     * of the directory that contains the new entry shall be marked for
     * update. */
    set_ts(NULL, &ps.st_mtim, &ps.st_ctim);
    ++(ps.num_ents);

    assert(ps.st_ino == k.ino);
    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err2;

    ret = inc_refcnt(opargs->be, opargs->ref_inodes, opargs->ino, 0, 0, 1,
                     opargs->refinop);
    if (ret != 0)
        goto err2;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err3;

    return 0;

err3:
    dec_refcnt(opargs->ref_inodes, 0, 0, -1, opargs->refinop[0]);
err2:
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, refinop);
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
    struct op_args *opargs = (struct op_args *)args;
    struct open_dir *odir;

    dump_db(opargs->be);

    ret = back_end_iter_new(&iter, opargs->be);
    if (ret != 0)
        return ret;

    odir = opargs->op_data.readdir_data.odir;

    k.type = TYPE_DIRENT;
    k.ino = odir->ino;
    strlcpy(k.name, odir->cur_name, sizeof(k.name));

    ret = back_end_iter_search(iter, &k);
    if (ret < 0)
        goto err;

    off = opargs->op_data.readdir_data.off;
    readdir_buf = opargs->op_data.readdir_data.buf;
    bufsize = opargs->op_data.readdir_data.bufsize;

    for (buflen = 0; buflen <= bufsize; buflen += entsize) {
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

        if ((k.ino != odir->ino) || (k.type != TYPE_DIRENT))
            break;

        strlcpy(odir->cur_name, k.name, sizeof(odir->cur_name));

        memset(&s, 0, sizeof(s));
        s.st_ino = buf.de.ino;

        remsize = bufsize - buflen;
        entsize = fuse_add_direntry(opargs->req, readdir_buf + buflen, remsize,
                                    k.name, &s, off + 1);
        if (entsize > remsize)
            goto end;

        ret = back_end_iter_next(iter);
        if (ret != 0) {
            if (ret != -EADDRNOTAVAIL)
                goto err;
            break;
        }

        ++off;
    }

    odir->cur_name[0] = '\0';

end:
    back_end_iter_free(iter);
    opargs->op_data.readdir_data.off = off;
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
    struct op_args *opargs = (struct op_args *)args;

    k.type = TYPE_STAT;
    k.ino = opargs->ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    return inc_refcnt(opargs->be, opargs->ref_inodes, opargs->ino, 0, 1, 0,
                      opargs->refinop);
}

static int
do_read(void *args)
{
    int count, iovsz;
    int i;
    int ret;
    off_t off;
    size_t size;
    struct db_key k;
    struct db_obj_stat s;
    struct iovec *iov;
    struct op_args *opargs = (struct op_args *)args;
    uint64_t firstpgidx, lastpgidx;

    k.type = TYPE_STAT;
    k.ino = opargs->ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    off = opargs->op_data.rdwr_data.off;

    if (off >= s.st_size) {
        opargs->op_data.rdwr_data.iov = NULL;
        opargs->op_data.rdwr_data.count = 0;
        return 0;
    }

    size = opargs->op_data.rdwr_data.size;

    firstpgidx = off / PG_SIZE;
    lastpgidx = (MIN(off + (off_t)size, s.st_size) - 1) / PG_SIZE;
    count = lastpgidx - firstpgidx + 1;

    iov = do_calloc(count, sizeof(*iov));
    if (iov == NULL)
        return MINUS_ERRNO;

    k.type = TYPE_PAGE;

    iovsz = 0;
    for (i = 0; i < count; i++) {
        char buf[PG_SIZE];
        size_t pgoff;
        size_t sz;

        k.pgno = off / PG_SIZE;

        pgoff = off - (k.pgno * PG_SIZE);

        sz = MIN((off_t)((k.pgno + 1) * PG_SIZE), s.st_size) - off;
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
do_write(void *args)
{
    const char *write_buf;
    int ret;
    off_t off;
    size_t size, write_size;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = (struct op_args *)args;

    k.type = TYPE_STAT;
    k.ino = opargs->ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    k.type = TYPE_PAGE;

    write_buf = opargs->op_data.rdwr_data.buf;
    off = opargs->op_data.rdwr_data.off;
    size = write_size = opargs->op_data.rdwr_data.size;
    while (size > 0) {
        char buf[PG_SIZE];
        size_t pgoff;
        size_t sz;

        k.pgno = off / PG_SIZE;

        pgoff = off - k.pgno * PG_SIZE;

        sz = (k.pgno + 1) * PG_SIZE - off;
        if (sz > size)
            sz = size;

        ret = back_end_look_up(opargs->be, &k, NULL, buf, NULL, 0);
        if (ret != 1) {
            if (ret != 0)
                return ret;

            memset(buf, 0, pgoff);
            memcpy(buf + pgoff, write_buf + write_size - size, sz);
            memset(buf + pgoff + sz, 0, sizeof(buf) - pgoff - sz);

            ret = back_end_insert(opargs->be, &k, buf, sizeof(buf));
        } else {
            memcpy(buf + pgoff, write_buf + write_size - size, sz);

            ret = back_end_replace(opargs->be, &k, buf, sizeof(buf));
        }
        if (ret != 0)
            return ret;

        off += sz;
        size -= sz;
    }

    if (off > s.st_size)
        s.st_size = off;
    /* POSIX-1.2008, write, para. 14:
     * Upon successful completion, where nbyte is greater than 0, write() shall
     * mark for update the last data modification and last file status change
     * timestamps of the file... */
    set_ts(NULL, &s.st_mtim, &s.st_ctim);

    k.type = TYPE_STAT;

    ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
    if (ret != 0)
        return ret;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err;

    return 0;

err:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_close(void *args)
{
    int ret;
    struct op_args *opargs = (struct op_args *)args;
    struct ref_ino refino, *refinop;

    refino.ino = opargs->ino;
    refinop = &refino;

    pthread_mutex_lock(&opargs->ref_inodes->ref_inodes_mtx);
    ret = avl_tree_search(opargs->ref_inodes->ref_inodes, &refinop, &refinop);
    pthread_mutex_unlock(&opargs->ref_inodes->ref_inodes_mtx);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    ret = unref_inode(opargs->be, opargs->ref_inodes, refinop, 0, -1, 0, NULL);
    if (ret != 0)
        return ret;

    pthread_mutex_lock(&opargs->ref_inodes->ref_inodes_mtx);
    if (!(refinop->nodelete) && (refinop->nlink == 0) && (refinop->refcnt == 0)
        && (refinop->nlookup == 0)) {
        if (avl_tree_delete(opargs->ref_inodes->ref_inodes, &refinop) == 0)
            free(refinop);
    }
    pthread_mutex_unlock(&opargs->ref_inodes->ref_inodes_mtx);

    return 0;
}

static int
do_sync(void *args)
{
    struct op_args *opargs = (struct op_args *)args;

    return back_end_sync(opargs->be);
}

static int
do_read_header(void *args)
{
    int ret;
    struct db_key k;
    struct op_args *opargs = (struct op_args *)args;

    k.type = TYPE_HEADER;
    ret = back_end_look_up(opargs->be, &k, NULL, &opargs->hdr, NULL, 0);
    if (ret != 1)
        return (ret == 0) ? -EILSEQ : ret;

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
    struct op_args *opargs = (struct op_args *)args;

    flags = opargs->op_data.xattr_data.flags;

    k.type = TYPE_XATTR;
    k.ino = opargs->ino;
    strlcpy(k.name, opargs->op_data.xattr_data.name, sizeof(k.name));

    value = opargs->op_data.xattr_data.value;
    size = opargs->op_data.xattr_data.size;

    if ((flags == 0) || (flags == XATTR_CREATE)) {
        ret = back_end_insert(opargs->be, &k, value, size);
        if ((ret != -EADDRINUSE) || (flags == XATTR_CREATE))
            return ret;
    } else if (flags != XATTR_REPLACE)
        return -EINVAL;

    return back_end_replace(opargs->be, &k, value, size);
}

static int
do_getxattr(void *args)
{
    char *value = NULL;
    int ret;
    size_t size, valsize;
    struct db_key k;
    struct op_args *opargs = (struct op_args *)args;

    size = opargs->op_data.xattr_data.size;

    k.type = TYPE_XATTR;
    k.ino = opargs->ino;
    strlcpy(k.name, opargs->op_data.xattr_data.name, sizeof(k.name));

    ret = back_end_look_up(opargs->be, &k, NULL, NULL, &valsize, 0);
    if (ret != 1)
        return (ret == 0) ? -EADDRNOTAVAIL : ret;
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
        return (ret == 0) ? -EIO : ret;
    }

end:
    opargs->op_data.xattr_data.value = value;
    opargs->op_data.xattr_data.size = valsize;
    return 0;
}

static int
do_listxattr(void *args)
{
    char *value;
    int ret;
    size_t bufsize;
    size_t len, size;
    struct back_end_iter *iter;
    struct db_key k;
    struct op_args *opargs = (struct op_args *)args;

    ret = back_end_iter_new(&iter, opargs->be);
    if (ret != 0)
        return ret;

    k.type = TYPE_XATTR;
    k.ino = opargs->ino;
    k.name[0] = '\0';

    ret = back_end_iter_search(iter, &k);
    if (ret < 0)
        goto err1;

    value = NULL;
    len = size = 0;
    for (;;) {
        ret = back_end_iter_get(iter, &k, NULL, NULL);
        if (ret != 0) {
            if (ret != -EADDRNOTAVAIL)
                goto err2;
            break;
        }

        if ((k.ino != opargs->ino) || (k.type != TYPE_XATTR))
            break;

        ret = add_xattr_name(&value, &len, &size, k.name);
        if (ret != 0)
            goto err2;

        ret = back_end_iter_next(iter);
        if (ret != 0) {
            if (ret != -EADDRNOTAVAIL)
                goto err2;
            break;
        }
    }

    bufsize = opargs->op_data.xattr_data.size;

    if (bufsize == 0) {
        if (value != NULL)
            free(value);
    } else if (bufsize < len) {
        ret = -ERANGE;
        goto err2;
    }

    back_end_iter_free(iter);

    opargs->op_data.xattr_data.value = value;
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
    struct db_key k;
    struct op_args *opargs = (struct op_args *)args;

    k.type = TYPE_XATTR;
    k.ino = opargs->ino;
    strlcpy(k.name, opargs->op_data.xattr_data.name, sizeof(k.name));

    return back_end_delete(opargs->be, &k);
}

static int
do_access(void *args)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = (struct op_args *)args;

    if (opargs->op_data.mask & F_OK) {
        k.type = TYPE_STAT;
        k.ino = opargs->ino;

        ret = back_end_look_up(opargs->be, &k, NULL, &s, NULL, 0);
        if (ret != 1)
            return (ret == 0) ? -ENOENT : ret;
    }

    return 0;
}

static int
do_create(void *args)
{
    const char *name;
    const struct fuse_ctx *ctx;
    fuse_ino_t parent;
    int ret;
    struct db_key k;
    struct db_obj_stat ps;
    struct op_args *opargs = (struct op_args *)args;

    ctx = opargs->ctx;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    parent = opargs->op_data.mknod_data.parent;
    name = opargs->op_data.mknod_data.name;

    /* POSIX-1.2008, open, para. 7:
     * If O_CREAT is set and the file did not previously exist, upon successful
     * completion, open() shall mark for update the last data access, last data
     * modification, and last file status change timestamps of the file... */
    ret = new_node(opargs->be, opargs->ref_inodes, parent, name, ctx->uid,
                   ctx->gid, opargs->op_data.mknod_data.mode & ~(ctx->umask), 0,
                   0, &opargs->attr, opargs->refinop, 1);
    if (ret != 0)
        goto err1;

    k.type = TYPE_STAT;
    k.ino = parent;

    ret = back_end_look_up(opargs->be, &k, NULL, &ps, NULL, 0);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err2;
    }

    /* ", open, para. 7:
     * If O_CREAT is set and the file did not previously exist, upon successful
     * completion, open() shall mark for update...the last data modification and
     * last file status change timestamps of the parent directory. */
    set_ts(NULL, &ps.st_mtim, &ps.st_ctim);

    ret = back_end_replace(opargs->be, &k, &ps, sizeof(ps));
    if (ret != 0)
        goto err2;

    ret = inc_refcnt(opargs->be, opargs->ref_inodes, opargs->attr.st_ino, 0, 1,
                     0, &opargs->refinop[2]);
    if (ret != 0)
        goto err2;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err3;

    dump_db(opargs->be);

    return 0;

err3:
    dec_refcnt(opargs->ref_inodes, 0, -1, 0, opargs->refinop[2]);
err2:
    dec_refcnt(opargs->ref_inodes, 0, 0, -1, opargs->refinop[1]);
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, opargs->refinop[0]);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

int
mount_status()
{
    int status;

    pthread_mutex_lock(&mtx);
    status = init;
    pthread_mutex_unlock(&mtx);

    return (status >= 0) ? 0 : status;
}

/*
 * Note: If the init request performs an unmount due to an error, a forget
 * request for the root I-node is immediately issued, no destroy request is
 * issued, and the FUSE processing loop blocks until the init request returns.
 */
static void
simplefs_init(void *userdata, struct fuse_conn_info *conn)
{
    int ret;
    struct db_args args;
    struct db_key k;
    struct db_obj_header hdr;
    struct fspriv *priv;
    struct mount_data *md = (struct mount_data *)userdata;
    struct ref_ino *refinop[4];

#if FUSE_USE_VERSION == 32
    conn->want = FUSE_CAP_ASYNC_READ | FUSE_CAP_EXPORT_SUPPORT
                 | FUSE_CAP_WRITEBACK_CACHE;
#else
    conn->want = FUSE_CAP_ASYNC_READ | FUSE_CAP_BIG_WRITES
                 | FUSE_CAP_EXPORT_SUPPORT;
#endif

    priv = do_malloc(sizeof(*priv));
    if (priv == NULL) {
        ret = MINUS_ERRNO;
        goto err1;
    }

    priv->wb_err = 0;

    ret = fifo_new(&priv->queue, sizeof(struct queue_elem *), 1024);
    if (ret != 0)
        goto err2;

    args.db_pathname = (md->db_pathname == NULL)
                       ? DB_PATHNAME : md->db_pathname;
    args.db_mode = ACC_MODE_DEFAULT;
    args.ro = md->ro;
    args.sync_cb = &sync_cb;
    args.sync_ctx = priv;

    ret = avl_tree_new(&priv->ref_inodes.ref_inodes, sizeof(struct ref_ino *),
                       &ref_inode_cmp, 0, NULL, NULL, NULL);
    if (ret != 0)
        goto err3;
    ret = -pthread_mutex_init(&priv->ref_inodes.ref_inodes_mtx, NULL);
    if (ret != 0)
        goto err4;

    ret = back_end_open(&priv->be, sizeof(struct db_key), &db_key_cmp, &args);
    if (ret != 0) {
        if (ret != -ENOENT)
            goto err5;

        if (args.ro) {
            fputs("Warning: Ignoring read-only mount flag (creating file "
                  "system)\n", stderr);
        }

        ret = back_end_create(&priv->be, sizeof(struct db_key), &db_key_cmp,
                              &args);
        if (ret != 0)
            goto err5;

        k.type = TYPE_HEADER;
        hdr.version = FMT_VERSION;
        hdr.next_ino = FUSE_ROOT_ID + 1;
        ret = back_end_insert(priv->be, &k, &hdr, sizeof(hdr));
        if (ret != 0)
            goto err6;

        /* create root directory */
        ret = new_dir(priv->be, &priv->ref_inodes, 0, NULL, getuid(), getgid(),
                      ROOT_DIR_INIT_PERMS, NULL, refinop, 0);
        if (ret != 0)
            goto err6;

        ret = back_end_sync(priv->be);
        if (ret != 0)
            goto err6;
    } else {
        k.type = TYPE_HEADER;

        ret = back_end_look_up(priv->be, &k, NULL, &hdr, NULL, 0);
        if (ret != 1) {
            if (ret == 0)
                ret = -EILSEQ;
            goto err6;
        }

        if (hdr.version != FMT_VERSION) {
            ret = -EPROTONOSUPPORT;
            goto err6;
        }
    }

    md->priv = priv;

    ret = -pthread_create(&priv->worker_td, NULL, &worker_td, md);
    if (ret != 0)
        goto err6;

    /* root I-node implicitly looked up on completion of init request */
    ret = inc_refcnt(priv->be, &priv->ref_inodes, FUSE_ROOT_ID, 0, 0, 1,
                     &refinop[0]);
    if (ret != 0)
        goto err7;

    write(SIMPLEFS_MOUNT_PIPE_FD, SIMPLEFS_MOUNT_PIPE_MSG_OK,
          sizeof(SIMPLEFS_MOUNT_PIPE_MSG_OK));

    pthread_mutex_lock(&mtx);
    init = 1;
    pthread_mutex_unlock(&mtx);

    syslog(LOG_INFO, FSNAME " using " LIBNAME " initialized successfully");

    return;

err7:
    join_worker(priv);
err6:
    back_end_close(priv->be);
err5:
    pthread_mutex_destroy(&priv->ref_inodes.ref_inodes_mtx);
err4:
    avl_tree_free(priv->ref_inodes.ref_inodes);
err3:
    fifo_free(priv->queue);
err2:
    free(priv);
err1:
    pthread_mutex_lock(&mtx);
    init = ret;
    pthread_mutex_unlock(&mtx);
    abort_init(-ret, "Error mounting FUSE file system");
}

static void
simplefs_destroy(void *userdata)
{
    avl_tree_walk_ctx_t wctx = NULL;
    int initialized;
    int ret, tmp;
    struct fspriv *priv;
    struct free_ref_inodes_ctx fctx;
    struct mount_data *md = (struct mount_data *)userdata;

    pthread_mutex_lock(&mtx);
    initialized = init;
    pthread_mutex_unlock(&mtx);
    if (initialized != 1)
        return;

    priv = md->priv;

    ret = join_worker(priv);

    /* Note: A resource leak in the file system will occur in the unlikely case
     * that free_ref_inodes_cb() fails. */
    fctx.priv = priv;
    fctx.err = 0;
    tmp = avl_tree_walk(priv->ref_inodes.ref_inodes, NULL, &free_ref_inodes_cb,
                        &fctx, &wctx);
    if (fctx.err)
        ret = fctx.err;
    else if (tmp != 0)
        ret = tmp;

    avl_tree_free(priv->ref_inodes.ref_inodes);

    pthread_mutex_destroy(&priv->ref_inodes.ref_inodes_mtx);

    tmp = back_end_close(priv->be);
    if (tmp != 0)
        ret = tmp;

    fifo_free(priv->queue);

    free(priv);

    pthread_mutex_lock(&mtx);
    init = ret;
    pthread_mutex_unlock(&mtx);

    if (ret == 0)
        syslog(LOG_INFO, FSNAME " terminated successfully");
    else
        syslog(LOG_ERR, FSNAME " terminated with error");
}

static void
simplefs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    int ret;
    struct fspriv *priv;
    struct fuse_entry_param e;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.k.type = TYPE_DIRENT;
    opargs.k.ino = parent;
    strlcpy(opargs.k.name, name, sizeof(opargs.k.name));

    opargs.op_data.inc_lookup_cnt = 1;

    ret = do_queue_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        if (ret != 0)
            goto err;
        e.ino = 0;
    } else {
        e.ino = opargs.s.st_ino;
        deserialize_stat(&e.attr, &opargs.s);
        if (S_ISDIR(e.attr.st_mode))
            e.attr.st_size = opargs.s.num_ents;
    }
    e.generation = 1;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;

    ret = fuse_reply_entry(req, &e);
    if (ret != 0) {
        if (e.ino != 0) {
            /* In the unlikely event that fuse_reply_entry() returns an error,
               this code will revert the changes made to the reference-counting
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
    fuse_reply_err(req, -ret);
}

static void
#if FUSE_USE_VERSION == 32
simplefs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
#else
simplefs_forget(fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
#endif
{
    int initialized;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    pthread_mutex_lock(&mtx);
    initialized = init;
    pthread_mutex_unlock(&mtx);
    if (initialized != 1) {
        /* forget request sent by unmounting before initialization finished
           successfully */
        return;
    }

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    opargs.op_data.nlookup = nlookup;

    do_queue_op(priv, &do_forget, &opargs);
    /* Note: A resource leak in the file system will occur in the unlikely case
     * that do_forget() fails. */

    fuse_reply_none(req);
}

static void
simplefs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;
    struct stat attr;

    (void)fi; /* fi is always NULL */

    priv = md->priv;

    opargs.be = priv->be;

    opargs.k.type = TYPE_STAT;
    opargs.k.ino = ino;

    opargs.op_data.inc_lookup_cnt = 0;

    ret = do_queue_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err;
    }

    deserialize_stat(&attr, &opargs.s);
    if (S_ISDIR(attr.st_mode))
        attr.st_size = opargs.s.num_ents;

    ret = fuse_reply_attr(req, &attr, CACHE_TIMEOUT);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set,
                 struct fuse_file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
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

    ret = fuse_reply_attr(req, &opargs.attr, CACHE_TIMEOUT);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_readlink(fuse_req_t req, fuse_ino_t ino)
{
    const char *link;
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    ret = do_queue_op(priv, &do_read_symlink, &opargs);
    if (ret != 0)
        goto err;

    link = (const char *)(opargs.op_data.rdwr_data.buf);

    ret = fuse_reply_readlink(req, link);
    free((void *)link);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
               dev_t rdev)
{
    int ret;
    struct fspriv *priv;
    struct fuse_entry_param e;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.ctx = fuse_req_ctx(req);

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = parent;

    opargs.op_data.mknod_data.name = name;
    opargs.op_data.mknod_data.mode = mode;
    opargs.op_data.mknod_data.rdev = rdev;

    ret = do_queue_op(priv, &do_create_node, &opargs);
    if (ret != 0)
        goto err;

    e.ino = opargs.attr.st_ino;
    e.generation = 1;
    e.attr = opargs.attr;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;
    ret = fuse_reply_entry(req, &e);
    if (ret != 0) {
        dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop[1]);
        if (ret != -ENOENT)
            goto err;
    }

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
    int ret;
    struct fspriv *priv;
    struct fuse_entry_param e;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.ctx = fuse_req_ctx(req);

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = parent;

    opargs.op_data.mknod_data.name = name;
    opargs.op_data.mknod_data.mode = mode;

    ret = do_queue_op(priv, &do_create_dir, &opargs);
    if (ret != 0)
        goto err;

    e.ino = opargs.attr.st_ino;
    e.generation = 1;
    e.attr = opargs.attr;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;
    ret = fuse_reply_entry(req, &e);
    if (ret != 0) {
        dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop[3]);
        if (ret != -ENOENT)
            goto err;
    }

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.k.type = TYPE_DIRENT;
    opargs.k.ino = parent;
    strlcpy(opargs.k.name, name, sizeof(opargs.k.name));

    opargs.op_data.inc_lookup_cnt = 0;

    ret = do_queue_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err;
    }

    opargs.ino = opargs.s.st_ino;

    opargs.op_data.link_data.parent = parent;
    opargs.op_data.link_data.name = name;

    ret = do_queue_op(priv, &do_remove_node_link, &opargs);
    if (ret != 0)
        goto err;

    ret = fuse_reply_err(req, 0);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    if ((strcmp(name, ".") == 0) || (strcmp(name, "..") == 0)) {
        ret = EINVAL;
        goto err;
    }

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.k.type = TYPE_DIRENT;
    opargs.k.ino = parent;
    strlcpy(opargs.k.name, name, sizeof(opargs.k.name));

    opargs.op_data.inc_lookup_cnt = 0;

    ret = do_queue_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err;
    }

    opargs.ino = opargs.s.st_ino;

    opargs.op_data.link_data.parent = parent;
    opargs.op_data.link_data.name = name;

    ret = do_queue_op(priv, &do_remove_dir, &opargs);
    if (ret != 0)
        goto err;

    ret = fuse_reply_err(req, 0);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
                 const char *name)
{
    int ret;
    struct fspriv *priv;
    struct fuse_entry_param e;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.ctx = fuse_req_ctx(req);

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.op_data.mknod_data.parent = parent;
    opargs.op_data.mknod_data.name = name;
    opargs.op_data.mknod_data.link = link;

    ret = do_queue_op(priv, &do_create_symlink, &opargs);
    if (ret != 0)
        goto err;

    e.ino = opargs.attr.st_ino;
    e.generation = 1;
    e.attr = opargs.attr;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;
    ret = fuse_reply_entry(req, &e);
    if (ret != 0) {
        dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop[1]);
        if (ret != -ENOENT)
            goto err;
    }

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
#if FUSE_USE_VERSION == 32
simplefs_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
                fuse_ino_t newparent, const char *newname, unsigned int flags)
#else
simplefs_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
                fuse_ino_t newparent, const char *newname)
#endif
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

#if FUSE_USE_VERSION == 32
    (void)flags;

#endif
    if ((strcmp(name, ".") == 0) || (strcmp(name, "..") == 0)
        || (strcmp(newname, ".") == 0) || (strcmp(newname, "..") == 0)) {
        ret = EINVAL;
        goto err;
    }

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.op_data.link_data.parent = parent;
    opargs.op_data.link_data.name = name;
    opargs.op_data.link_data.newparent = newparent;
    opargs.op_data.link_data.newname = newname;

    ret = do_queue_op(priv, &do_rename, &opargs);
    if (ret != 0)
        goto err;

    ret = fuse_reply_err(req, 0);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
              const char *newname)
{
    int ret;
    struct fspriv *priv;
    struct fuse_entry_param e;
    struct mount_data *md = fuse_req_userdata(req);
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

    e.ino = opargs.s.st_ino;
    e.generation = 1;
    deserialize_stat(&e.attr, &opargs.s);
    if (S_ISDIR(e.attr.st_mode))
        e.attr.st_size = opargs.s.num_ents;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;

    ret = fuse_reply_entry(req, &e);
    if (ret != 0) {
        dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop[0]);
        if (ret != -ENOENT)
            goto err;
    }

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    int interrupted = 0;
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;
    struct open_file *ofile;

    if (md->ro && ((fi->flags & O_ACCMODE) != O_RDONLY)) {
        ret = -EROFS;
        goto err1;
    }

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    ofile = do_malloc(sizeof(*ofile));
    if (ofile == NULL) {
        ret = MINUS_ERRNO;
        goto err1;
    }

    ret = do_queue_op(priv, &do_open, &opargs);
    if (ret != 0)
        goto err2;

    ofile->ino = ino;

    fi->fh = (uintptr_t)ofile;
    fi->keep_cache = KEEP_CACHE_OPEN;

    ret = fuse_reply_open(req, fi);
    if (ret != 0) {
        if (ret == -ENOENT)
            interrupted = 1;
        goto err3;
    }

    return;

err3:
    do_queue_op(priv, &do_close, &opargs);
err2:
    free(ofile);
err1:
    if (!interrupted)
        fuse_reply_err(req, -ret);
}

static void
simplefs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
              struct fuse_file_info *fi)
{
    int count;
    int ret;
    struct fspriv *priv;
    struct iovec *iov;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    (void)fi; /* VFS handles file descriptor access mode check on Linux */

    if (size == 0) {
        ret = fuse_reply_iov(req, NULL, 0);
        if ((ret != 0) && (ret != -ENOENT))
            goto err;
        return;
    }

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.op_data.rdwr_data.size = size;
    opargs.op_data.rdwr_data.off = off;

    ret = do_queue_op(priv, &do_read, &opargs);
    if (ret != 0)
        goto err;

    iov = opargs.op_data.rdwr_data.iov;
    count = opargs.op_data.rdwr_data.count;

    ret = fuse_reply_iov(req, iov, count);
    free_iov(iov, count);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size,
               off_t off, struct fuse_file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    /* VFS handles file descriptor access mode check on Linux */
    /* fi->fh guessed if called by writeback */
    (void)fi;

    if (size == 0) {
        ret = fuse_reply_write(req, 0);
        if ((ret != 0) && (ret != -ENOENT))
            goto err;
        return;
    }

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.op_data.rdwr_data.buf = (char *)buf;
    opargs.op_data.rdwr_data.size = size;
    opargs.op_data.rdwr_data.off = off;

    ret = do_queue_op(priv, &do_write, &opargs);
    if (ret != 0)
        goto err;

    ret = fuse_reply_write(req, size);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);

    (void)ino;
    (void)fi;

    priv = md->priv;

    ret = fuse_reply_err(req, -(priv->wb_err));
    if ((ret != 0) && (ret != -ENOENT))
        fuse_reply_err(req, -ret);
}

static void
simplefs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    int interrupted = 0;
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;
    struct open_dir *odir;

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    odir = do_malloc(sizeof(*odir));
    if (odir == NULL) {
        ret = MINUS_ERRNO;
        goto err1;
    }

    ret = do_queue_op(priv, &do_open, &opargs);
    if (ret != 0)
        goto err2;

    odir->ino = ino;
    odir->cur_name[0] = '\0';

    fi->fh = (uintptr_t)odir;
    fi->keep_cache = KEEP_CACHE_OPEN;

    ret = fuse_reply_open(req, fi);
    if (ret != 0) {
        if (ret == -ENOENT)
            interrupted = 1;
        goto err3;
    }

    return;

err3:
    do_queue_op(priv, &do_close, &opargs);
err2:
    free(odir);
err1:
    if (!interrupted)
        fuse_reply_err(req, -ret);
}

static void
simplefs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                 struct fuse_file_info *fi)
{
    char *buf;
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;
    struct open_dir *odir = (struct open_dir *)(uintptr_t)(fi->fh);

    (void)ino;

    if ((off > 0) && (odir->cur_name[0] == '\0')) {
        ret = fuse_reply_buf(req, NULL, 0);
        if ((ret != 0) && (ret != -ENOENT))
            goto err;
        return;
    }

    priv = md->priv;

    buf = do_malloc(size);
    if (buf == NULL) {
        ret = errno;
        goto err;
    }

    opargs.req = req;

    opargs.be = priv->be;

    opargs.op_data.readdir_data.odir = odir;
    opargs.op_data.readdir_data.buf = buf;
    opargs.op_data.readdir_data.bufsize = size;
    opargs.op_data.readdir_data.off = off;

    ret = do_queue_op(priv, &do_read_entries, &opargs);
    if (ret != 0) {
        free(buf);
        goto err;
    }

    ret = fuse_reply_buf(req, buf, opargs.op_data.readdir_data.buflen);
    free(buf);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;
    struct open_file *ofile;

    priv = md->priv;

    ofile = (struct open_file *)(uintptr_t)(fi->fh);

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    ret = do_queue_op(priv, &do_close, &opargs);

    free(ofile);

    fuse_reply_err(req, -ret);
}

static void
simplefs_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
               struct fuse_file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
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

    ret = fuse_reply_err(req, -ret);
    if ((ret != 0) && (ret != -ENOENT))
        fuse_reply_err(req, -ret);
}

static void
simplefs_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;
    struct open_dir *odir;

    priv = md->priv;

    odir = (struct open_dir *)(uintptr_t)(fi->fh);

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    ret = do_queue_op(priv, &do_close, &opargs);

    free(odir);

    fuse_reply_err(req, -ret);
}

static void
simplefs_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
                  struct fuse_file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
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

    ret = fuse_reply_err(req, -ret);
    if ((ret != 0) && (ret != -ENOENT))
        fuse_reply_err(req, -ret);
}

static void
simplefs_statfs(fuse_req_t req, fuse_ino_t ino)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;
    struct statvfs stbuf;

    (void)ino;

    priv = md->priv;

    if (statvfs(".", &stbuf) == -1) {
        ret = errno;
        goto err;
    }

    opargs.be = priv->be;

    ret = do_queue_op(priv, &do_read_header, &opargs);
    if (ret != 0)
        goto err;

    stbuf.f_blocks = (stbuf.f_blocks * stbuf.f_frsize) / PG_SIZE;
    stbuf.f_bfree = (stbuf.f_bfree * stbuf.f_bsize) / PG_SIZE;
    stbuf.f_bavail = (stbuf.f_bavail * stbuf.f_bsize) / PG_SIZE;

    stbuf.f_bsize = PG_SIZE;
    stbuf.f_frsize = PG_SIZE;

    stbuf.f_files = (fsfilcnt_t)ULONG_MAX;
    stbuf.f_ffree = stbuf.f_favail = (fsfilcnt_t)(stbuf.f_files
                                                  - opargs.hdr.next_ino + 1);

    stbuf.f_fsid = 0;

    stbuf.f_flag = 0;

    stbuf.f_namemax = NAME_MAX;

    ret = fuse_reply_statfs(req, &stbuf);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

#ifdef __APPLE__
static void
simplefs_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                  const char *value, size_t size, int flags, uint32_t position)
#else
static void
simplefs_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                  const char *value, size_t size, int flags)
#endif
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

#ifdef __APPLE__
    if (position > 0) {
        ret = -ENOTSUP;
        goto err;
    }

#endif
    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.op_data.xattr_data.name = name;
    opargs.op_data.xattr_data.value = (char *)value;
    opargs.op_data.xattr_data.size = size;
    opargs.op_data.xattr_data.flags = flags;

    ret = do_queue_op(priv, &do_setxattr, &opargs);
    if (ret != 0)
        goto err;

    ret = fuse_reply_err(req, -ret);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

#ifdef __APPLE__
static void
simplefs_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size,
                  uint32_t position)
#else
static void
simplefs_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
#endif
{
    char *value;
    int ret;
    size_t valsize;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

#ifdef __APPLE__
    if (position > 0) {
        ret = -ENOTSUP;
        goto err;
    }

#endif
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
        ret = fuse_reply_xattr(req, valsize);
        if ((ret != 0) && (ret != -ENOENT))
            goto err;
        return;
    }

    value = opargs.op_data.xattr_data.value;

    ret = fuse_reply_buf(req, value, valsize);

    if (value != NULL)
        free(value);

    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
    char *value;
    int ret;
    size_t bufsize;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
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
        ret = fuse_reply_xattr(req, bufsize);
        if ((ret != 0) && (ret != -ENOENT))
            goto err;
        return;
    }

    value = opargs.op_data.xattr_data.value;

    ret = fuse_reply_buf(req, value, bufsize);

    if (value != NULL)
        free(value);

    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
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

    ret = fuse_reply_err(req, -ret);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.op_data.mask = mask;

    ret = do_queue_op(priv, &do_access, &opargs);
    if (ret != 0)
        goto err;

    ret = fuse_reply_err(req, -ret);
    if ((ret != 0) && (ret != -ENOENT))
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
                mode_t mode, struct fuse_file_info *fi)
{
    int interrupted = 0;
    int ret;
    struct fspriv *priv;
    struct fuse_entry_param e;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;
    struct open_file *ofile;

    if (md->ro && ((fi->flags & O_ACCMODE) != O_RDONLY)) {
        ret = -EROFS;
        goto err1;
    }

    priv = md->priv;

    opargs.ctx = fuse_req_ctx(req);

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.op_data.mknod_data.parent = parent;
    opargs.op_data.mknod_data.name = name;
    opargs.op_data.mknod_data.mode = mode;

    ofile = do_malloc(sizeof(*ofile));
    if (ofile == NULL) {
        ret = MINUS_ERRNO;
        goto err1;
    }

    ret = do_queue_op(priv, &do_create, &opargs);
    if (ret != 0)
        goto err2;

    ofile->ino = opargs.attr.st_ino;

    fi->fh = (uintptr_t)ofile;
    fi->keep_cache = KEEP_CACHE_OPEN;

    e.ino = opargs.attr.st_ino;
    e.generation = 1;
    e.attr = opargs.attr;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;
    ret = fuse_reply_create(req, &e, fi);
    if (ret != 0) {
        if (ret == -ENOENT)
            interrupted = 1;
        goto err3;
    }

    return;

err3:
    do_queue_op(priv, &do_close, &opargs);
    dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop[1]);
err2:
    free(ofile);
err1:
    if (!interrupted)
        fuse_reply_err(req, -ret);
}

struct fuse_lowlevel_ops simplefs_ops = {
    .init           = &simplefs_init,
    .destroy        = &simplefs_destroy,
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
    .create         = &simplefs_create
};

/* vi: set expandtab sw=4 ts=4: */
