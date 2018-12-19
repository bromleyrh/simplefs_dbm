/*
 * ops.c
 */

#include "back_end.h"
#include "ops.h"
#include "simplefs.h"
#include "util.h"

#include <fifo.h>

#include <files/acc_ctl.h>

#include <fuse.h>
#include <fuse_lowlevel.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/mount.h>
#include <sys/stat.h>

struct fspriv {
    struct back_end *be;
    struct fifo     *db_queue;
    pthread_t       worker_td;
};

struct db_queue_elem {
    int             (*op)(void *);
    void            *args;
    pthread_mutex_t mtx;
    pthread_cond_t  cv;
    int             ret;
};

enum db_obj_type {
    TYPE_DIRENT = 1,    /* look up by ino, name */
    TYPE_STAT,          /* look up by ino */
    TYPE_PAGE           /* look up by ino, pgno */
};

struct db_key {
    enum db_obj_type    type;
    uint64_t            ino;
    uint64_t            pgno;
    const char          name[NAME_MAX+1];
} __attribute__((packed));

struct disk_timespec {
    int32_t tv_sec;
    int32_t tv_nsec;
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
    struct disk_timespec    st_atim;
    struct disk_timespec    st_mtim;
    struct disk_timespec    st_ctim;
} __attribute__((packed));

struct db_obj_dirent {
    uint64_t ino;
} __attribute__((packed));

struct op_args {
    struct back_end     *be;
    struct db_key       k;
    struct db_obj_stat  s;
};

#define PGSIZE 4096

#define DB_PATHNAME "fs.db"

#define OP_RET_NONE INT_MAX

static void verror(int, const char *, va_list);

static int uint64_cmp(uint64_t, uint64_t);

static int db_key_cmp(const void *, const void *, void *);

static void *worker_td(void *);

static int do_back_end_op(struct fspriv *, int (*)(void *), void *);

static int join_worker(struct fspriv *);

static void do_set_ts(struct disk_timespec *);
static void set_ts(struct disk_timespec *, struct disk_timespec *,
                   struct disk_timespec *);
static void deserialize_ts(struct timespec *, struct disk_timespec *);

static void abort_init(struct mount_data *, int, const char *, ...);

static int new_dir(struct back_end *, fuse_ino_t, const char *, uid_t, gid_t,
                   mode_t);

static int do_look_up(void *);

static void simplefs_init(void *, struct fuse_conn_info *);
static void simplefs_destroy(void *);

static void
verror(int err, const char *fmt, va_list ap)
{
    char buf[128];

    vsnprintf(buf, sizeof(buf), fmt, ap);

    if (err)
        perror(buf);
    else {
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
db_key_cmp(const void *k1, const void *k2, void *key_ctx)
{
    int cmp;
    struct db_key *key1 = (struct db_key *)k1;
    struct db_key *key2 = (struct db_key *)k2;

    (void)key_ctx;

    cmp = uint64_cmp(key1->type, key2->type);
    if (cmp != 0)
        return cmp;

    cmp = uint64_cmp(key1->ino, key2->ino);
    if (cmp != 0)
        return cmp;

    switch (key1->type) {
    case TYPE_DIRENT:
        cmp = strcmp(key1->name, key2->name);
    case TYPE_STAT:
        break;
    case TYPE_PAGE:
        cmp = uint64_cmp(key1->pgno, key2->pgno);
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
    struct db_queue_elem *op;
    struct fspriv *priv;
    struct mount_data *md = (struct mount_data *)args;

    priv = md->priv;

    for (;;) {
        ret = fifo_get(priv->db_queue, &op);
        if (ret != 0)
            break;
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
do_back_end_op(struct fspriv *fspriv, int (*op_fn)(void *), void *args)
{
    int err;
    struct db_queue_elem op, *opp;

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
    err = fifo_put(fspriv->db_queue, &opp);
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
    struct db_queue_elem op, *opp;
    void *retval;

    op.op = NULL;
    opp = &op;
    err = fifo_put(priv->db_queue, &opp);
    if (err)
        return err;

    err = -pthread_join(priv->worker_td, &retval);

    return err ? err : (intptr_t)retval;
}

static void
do_set_ts(struct disk_timespec *ts)
{
    struct timespec timespec;

    if (clock_gettime(CLOCK_REALTIME, &timespec) == 0) {
        ts->tv_sec = timespec.tv_sec;
        ts->tv_nsec = timespec.tv_nsec;
    } else
        memset(ts, 0, sizeof(*ts));
}

static void
set_ts(struct disk_timespec *atim, struct disk_timespec *mtim,
       struct disk_timespec *ctim)
{
    if (atim != NULL)
        do_set_ts(atim);
    if (mtim != NULL)
        do_set_ts(mtim);
    if (ctim != NULL)
        do_set_ts(ctim);
}

static void
deserialize_ts(struct timespec *ts, struct disk_timespec *disk_ts)
{
    ts->tv_sec = disk_ts->tv_sec;
    ts->tv_nsec = disk_ts->tv_nsec;
}

static void
abort_init(struct mount_data *md, int err, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    verror(err, fmt, ap);
    va_end(ap);

    if (umount(md->mountpoint) == -1)
        abort();
}

static int
new_dir(struct back_end *be, fuse_ino_t parent, const char *name, uid_t uid,
        gid_t gid, mode_t mode)
{
    int err;

    (void)name;

    if (parent == 0) {
        struct db_key k;
        struct db_obj_stat s;

        k.type = TYPE_STAT;
        k.ino = FUSE_ROOT_ID;

        s.st_dev = 64 * 1024;
        s.st_ino = FUSE_ROOT_ID;
        s.st_mode = S_IFDIR | (mode & ALLPERMS);
        s.st_nlink = 2;
        s.st_uid = uid;
        s.st_gid = gid;
        s.st_rdev = 0;
        s.st_size = 2;
        s.st_blksize = PGSIZE;
        s.st_blocks = 0;
        set_ts(&s.st_atim, &s.st_mtim, &s.st_ctim);

        return back_end_insert(be, &k, &s, sizeof(s));
    }

    return 0;
}

static int
do_look_up(void *args)
{
    struct op_args *opargs = (struct op_args *)args;

    return back_end_look_up(opargs->be, &opargs->k, &opargs->s);
}

static void
simplefs_init(void *userdata, struct fuse_conn_info *conn)
{
    int err;
    struct db_args args;
    struct fspriv *priv;
    struct fuse_context *ctx = fuse_get_context();
    struct mount_data *md = (struct mount_data *)userdata;

    conn->want = FUSE_CAP_ATOMIC_O_TRUNC | FUSE_CAP_EXPORT_SUPPORT;

    priv = do_malloc(sizeof(*priv));
    if (priv == NULL) {
        err = -errno;
        goto err1;
    }

    err = fifo_new(&priv->db_queue, sizeof(struct db_queue_elem *), 1024);
    if (err)
        goto err2;

    args.db_pathname = DB_PATHNAME;
    args.db_mode = ACC_MODE_DEFAULT;

    err = back_end_open(&priv->be, sizeof(struct db_key), &db_key_cmp, &args);
    if (err) {
        if (err != -ENOENT)
            goto err3;

        err = back_end_create(&priv->be, sizeof(struct db_key), &db_key_cmp,
                              &args);
        if (err)
            goto err3;

        /* create root directory */
        err = new_dir(priv->be, 0, NULL, ctx->uid, ctx->gid,
                      ACCESSPERMS & ~(ctx->umask));
        if (err)
            goto err4;
    }

    md->priv = priv;

    err = -pthread_create(&priv->worker_td, NULL, &worker_td, md);
    if (err)
        goto err4;

    return;

err4:
    back_end_close(priv->be);
err3:
    fifo_free(priv->db_queue);
err2:
    free(priv);
err1:
    abort_init(md, -err, "Error mounting FUSE file system");
}

static void
simplefs_destroy(void *userdata)
{
    struct fspriv *priv;
    struct mount_data *md = (struct mount_data *)userdata;

    priv = (struct fspriv *)(md->priv);

    join_worker(priv);

    back_end_close(priv->be);

    fifo_free(priv->db_queue);

    free(priv);
}

static void
simplefs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;
    struct stat attr;

    (void)fi;

    priv = (struct fspriv *)(md->priv);

    opargs.be = priv->be;

    opargs.k.type = TYPE_STAT;
    opargs.k.ino = ino;

    ret = do_back_end_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        fuse_reply_err(req, (ret == 0) ? ENOENT : -ret);
        return;
    }

    attr.st_dev = opargs.s.st_dev;
    attr.st_ino = opargs.s.st_ino;
    attr.st_mode = opargs.s.st_mode;
    attr.st_nlink = opargs.s.st_nlink;
    attr.st_uid = opargs.s.st_uid;
    attr.st_gid = opargs.s.st_gid;
    attr.st_rdev = opargs.s.st_rdev;
    attr.st_size = opargs.s.st_size;
    attr.st_blksize = opargs.s.st_blksize;
    attr.st_blocks = opargs.s.st_blocks;
    deserialize_ts(&attr.st_atim, &opargs.s.st_atim);
    deserialize_ts(&attr.st_mtim, &opargs.s.st_mtim);
    deserialize_ts(&attr.st_ctim, &opargs.s.st_ctim);

    fuse_reply_attr(req, &attr, 0.0);
}

struct fuse_lowlevel_ops simplefs_ops = {
    .init       = &simplefs_init,
    .destroy    = &simplefs_destroy,
    .getattr    = &simplefs_getattr
};

/* vi: set expandtab sw=4 ts=4: */
