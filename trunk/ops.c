/*
 * ops.c
 */

#include "back_end.h"
#include "ops.h"
#include "simplefs.h"
#include "util.h"

#include <fifo.h>
#include <strings_ext.h>

#include <files/acc_ctl.h>

#include <fuse.h>
#include <fuse_lowlevel.h>

#include <assert.h>
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
    TYPE_HEADER = 1,
    TYPE_DIRENT,        /* look up by ino, name */
    TYPE_STAT,          /* look up by ino */
    TYPE_PAGE           /* look up by ino, pgno */
};

struct db_key {
    enum db_obj_type    type;
    uint64_t            ino;
    uint64_t            pgno;
    char                name[NAME_MAX+1];
} __attribute__((packed));

struct disk_timespec {
    int32_t tv_sec;
    int32_t tv_nsec;
} __attribute__((packed));

struct db_obj_header {
    uint64_t next_ino;
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
    struct disk_timespec    st_atim;
    struct disk_timespec    st_mtim;
    struct disk_timespec    st_ctim;
} __attribute__((packed));

struct op_args {
    fuse_req_t          req;
    struct back_end     *be;
    struct db_key       k;
    struct db_obj_stat  s;
    /* mkdir() */
    fuse_ino_t          parent;
    const char          *name;
    mode_t              mode;
    struct stat         attr;
    /* readdir() */
    struct open_dir     *odir;
    char                *buf;
    size_t              bufsize;
    size_t              buflen;
    off_t               off;
};

struct open_dir {
    char        cur_name[NAME_MAX+1];
    fuse_ino_t  ino;
};

#define PGSIZE 4096

#define DB_PATHNAME "fs.db"

#define OP_RET_NONE INT_MAX

#define DB_OBJ_MAX_SIZE (sizeof(struct db_obj_stat))

#define NAME_CUR_DIR "."
#define NAME_PARENT_DIR ".."

static void verror(int, const char *, va_list);

static int uint64_cmp(uint64_t, uint64_t);

static int db_key_cmp(const void *, const void *, struct back_end_key_ctx *);

static void *worker_td(void *);

static int do_back_end_op(struct fspriv *, int (*)(void *), void *);

static int join_worker(struct fspriv *);

static int dump_cb(const void *, const void *, size_t, void *);
static int dump_db(struct back_end *);

static int get_next_ino(struct back_end *, fuse_ino_t *);

static void do_set_ts(struct disk_timespec *);
static void set_ts(struct disk_timespec *, struct disk_timespec *,
                   struct disk_timespec *);
static void deserialize_ts(struct timespec *, struct disk_timespec *);

static void deserialize_stat(struct stat *, struct db_obj_stat *);

static void abort_init(struct mount_data *, int, const char *, ...);

static int new_dir(struct back_end *, fuse_ino_t, const char *, uid_t, gid_t,
                   mode_t, struct stat *);

static int new_dir_link(struct back_end *, fuse_ino_t, fuse_ino_t,
                        const char *);

static int do_look_up(void *);
static int do_create_dir(void *);
static int do_read_entries(void *);

static void simplefs_init(void *, struct fuse_conn_info *);
static void simplefs_destroy(void *);
static void simplefs_lookup(fuse_req_t, fuse_ino_t, const char *name);
static void simplefs_getattr(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void simplefs_mkdir(fuse_req_t, fuse_ino_t, const char *, mode_t);
static void simplefs_opendir(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void simplefs_readdir(fuse_req_t, fuse_ino_t, size_t, off_t,
                             struct fuse_file_info *);
static void simplefs_releasedir(fuse_req_t, fuse_ino_t,
                                struct fuse_file_info *);

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

static int
dump_cb(const void *key, const void *data, size_t datasize, void *ctx)
{
    struct db_key *k = (struct db_key *)key;
    struct db_obj_dirent *de;
    struct db_obj_header *hdr;
    struct db_obj_stat *s;

    switch (k->type) {
    case TYPE_HEADER:
        assert(datasize == sizeof(*hdr));
        hdr = (struct db_obj_header *)data;

        fprintf(stderr, "Header: next_ino %lu\n",
                (unsigned long)(hdr->next_ino));
        break;
    case TYPE_DIRENT:
        assert(datasize == sizeof(*de));
        de = (struct db_obj_dirent *)data;

        fprintf(stderr, "Directory entry: directory %lu, name %s -> node %lu\n",
                k->ino, k->name, de->ino);
        break;
    case TYPE_STAT:
        assert(datasize == sizeof(*s));
        s = (struct db_obj_stat *)data;

        fprintf(stderr, "I-node entry: node %lu -> st_ino %lu \n", k->ino,
                s->st_ino);
        break;
    default:
        abort();
    }

    return 0;
}

static int
dump_db(struct back_end *be)
{
#ifndef NDEBUG
    return back_end_walk(be, &dump_cb, NULL);
#else
    (void)be;

    return 0;
#endif
}

static int
get_next_ino(struct back_end *be, fuse_ino_t *ino)
{
    fuse_ino_t ret;
    int res;
    struct db_key k;
    struct db_obj_header hdr;

    k.type = TYPE_HEADER;
    res = back_end_look_up(be, &k, NULL, &hdr);
    if (res != 1)
        return (res == 0) ? -EILSEQ : res;

    if (hdr.next_ino == ULONG_MAX) {
        fputs("All I-node numbers consumed\n", stderr);
        abort();
    }
    ret = (hdr.next_ino)++;

    res = back_end_replace(be, &k, &hdr, sizeof(hdr));
    if (res != 0)
        return res;

    *ino = ret;
    return 0;
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
        gid_t gid, mode_t mode, struct stat *attr)
{
    fuse_ino_t ino;
    int err;
    int rootdir = (parent == 0);
    struct db_key k;
    struct db_obj_stat s;

    err = back_end_trans_new(be);
    if (err)
        return err;

    if (rootdir)
        parent = ino = FUSE_ROOT_ID;
    else {
        err = get_next_ino(be, &ino);
        if (err)
            return err;
    }

    k.type = TYPE_STAT;
    k.ino = ino;

    s.st_dev = 64 * 1024;
    s.st_ino = ino;
    s.st_mode = S_IFDIR | (mode & ALLPERMS);
    s.st_nlink = 2;
    s.st_uid = uid;
    s.st_gid = gid;
    s.st_rdev = 0;
    s.st_size = 2;
    s.st_blksize = PGSIZE;
    s.st_blocks = 0;
    set_ts(&s.st_atim, &s.st_mtim, &s.st_ctim);

    err = back_end_insert(be, &k, &s, sizeof(s));
    if (err)
        goto err;

    err = new_dir_link(be, ino, ino, NAME_CUR_DIR);
    if (err)
        goto err;
    err = new_dir_link(be, parent, ino, NAME_PARENT_DIR);
    if (err)
        goto err;

    if (!rootdir) {
        err = new_dir_link(be, ino, parent, name);
        if (err)
            goto err;
    }

    err = back_end_trans_commit(be);
    if (err)
        goto err;

    if (attr != NULL)
        deserialize_stat(attr, &s);

    return 0;

err:
    back_end_trans_abort(be);
    return err;
}

static int
new_dir_link(struct back_end *be, fuse_ino_t ino, fuse_ino_t newparent,
             const char *newname)
{
    struct db_key k;
    struct db_obj_dirent de;

    k.type = TYPE_DIRENT;
    k.ino = newparent;
    strlcpy(k.name, newname, sizeof(k.name));

    de.ino = ino;

    return back_end_insert(be, &k, &de, sizeof(de));
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
        ret = back_end_look_up(opargs->be, &opargs->k, NULL, &de);
        if (ret != 1)
            return ret;

        k.type = TYPE_STAT;
        k.ino = de.ino;
        return back_end_look_up(opargs->be, &k, NULL, &opargs->s);
    case TYPE_STAT:
        return back_end_look_up(opargs->be, &opargs->k, NULL, &opargs->s);
    default:
        return -EIO;
    }

    return 0;
}

static int
do_create_dir(void *args)
{
    int err;
    struct fuse_context *ctx = fuse_get_context();
    struct op_args *opargs = (struct op_args *)args;

    err = new_dir(opargs->be, opargs->parent, opargs->name, ctx->uid, ctx->gid,
                  opargs->mode & ~(ctx->umask), &opargs->attr);
    if (err)
        return err;

    dump_db(opargs->be);

    return 0;
}

static int
do_read_entries(void *args)
{
    int ret;
    size_t entsize;
    struct back_end_iter *iter;
    struct db_key k;
    struct op_args *opargs = (struct op_args *)args;

    dump_db(opargs->be);

    ret = back_end_iter_new(&iter, opargs->be);
    if (ret != 0)
        return ret;

    k.type = TYPE_DIRENT;
    k.ino = opargs->odir->ino;
    strlcpy(k.name, opargs->odir->cur_name, sizeof(k.name));

    ret = back_end_iter_search(iter, &k);
    if (ret < 0)
        goto err;

    for (opargs->buflen = 0; opargs->buflen < opargs->bufsize;
         opargs->buflen += entsize) {
        size_t remsize;
        struct stat s;
        union {
            struct db_obj_dirent    de;
            char                    buf[DB_OBJ_MAX_SIZE];
        } buf;

        ret = back_end_iter_get(iter, &k, &buf);
        if (ret != 0) {
            if (ret != -EADDRNOTAVAIL)
                goto err;
            break;
        }

        if ((k.ino != opargs->odir->ino) || (k.type != TYPE_DIRENT))
            break;

        strlcpy(opargs->odir->cur_name, k.name, sizeof(opargs->odir->cur_name));

        memset(&s, 0, sizeof(s));
        s.st_ino = buf.de.ino;

        remsize = opargs->bufsize - opargs->buflen;
        entsize = fuse_add_direntry(opargs->req, opargs->buf + opargs->buflen,
                                    remsize, k.name, &s, opargs->off + 1);
        if (entsize > remsize)
            goto end;

        ret = back_end_iter_next(iter);
        if (ret != 0) {
            if (ret != -EADDRNOTAVAIL)
                goto err;
            break;
        }

        ++(opargs->off);
    }

    opargs->odir->cur_name[0] = '\0';

end:
    back_end_iter_free(iter);
    return 0;

err:
    back_end_iter_free(iter);
    return ret;
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
        struct db_key k;
        struct db_obj_header hdr;

        if (err != -ENOENT)
            goto err3;

        err = back_end_create(&priv->be, sizeof(struct db_key), &db_key_cmp,
                              &args);
        if (err)
            goto err3;

        k.type = TYPE_HEADER;
        hdr.next_ino = FUSE_ROOT_ID + 1;
        err = back_end_insert(priv->be, &k, &hdr, sizeof(hdr));
        if (err)
            goto err4;

        /* create root directory */
        err = new_dir(priv->be, 0, NULL, ctx->uid, ctx->gid,
                      ACCESSPERMS & ~(ctx->umask), NULL);
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
simplefs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    int ret;
    struct fspriv *priv;
    struct fuse_entry_param e;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    priv = (struct fspriv *)(md->priv);

    opargs.be = priv->be;

    opargs.k.type = TYPE_DIRENT;
    opargs.k.ino = parent;
    strlcpy(opargs.k.name, name, sizeof(opargs.k.name));

    ret = do_back_end_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        ret = (ret == 0) ? ENOENT : -ret;
        goto err;
    }

    e.ino = opargs.s.st_ino;
    deserialize_stat(&e.attr, &opargs.s);
    e.attr_timeout = e.entry_timeout = 600.0;

    ret = fuse_reply_entry(req, &e);
    if (ret != 0)
        goto err;

    return;

err:
    fuse_reply_err(req, ret);
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

    priv = (struct fspriv *)(md->priv);

    opargs.be = priv->be;

    opargs.k.type = TYPE_STAT;
    opargs.k.ino = ino;

    ret = do_back_end_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        ret = (ret == 0) ? ENOENT : -ret;
        goto err;
    }

    deserialize_stat(&attr, &opargs.s);

    ret = fuse_reply_attr(req, &attr, 0.0);
    if (ret != 0)
        goto err;

    return;

err:
    fuse_reply_err(req, ret);
}

static void
simplefs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
    int ret;
    struct fspriv *priv;
    struct fuse_entry_param e;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    priv = (struct fspriv *)(md->priv);

    opargs.be = priv->be;

    opargs.parent = parent;
    opargs.name = name;
    opargs.mode = mode;

    ret = do_back_end_op(priv, &do_create_dir, &opargs);
    if (ret != 0)
        goto err;

    e.ino = opargs.attr.st_ino;
    e.generation = 1;
    e.attr = opargs.attr;
    e.attr_timeout = e.entry_timeout = 600.0;
    ret = fuse_reply_entry(req, &e);
    if (ret != 0)
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    int ret;
    struct open_dir *odir;

    odir = do_malloc(sizeof(*odir));
    if (odir == NULL) {
        ret = errno;
        goto err;
    }

    odir->ino = ino;
    odir->cur_name[0] = '\0';

    fi->fh = (uintptr_t)odir;

    ret = -fuse_reply_open(req, fi);
    if (ret != 0) {
        free(odir);
        goto err;
    }

    return;

err:
    fuse_reply_err(req, ret);
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
    struct open_dir *odir = (struct open_dir *)(fi->fh);

    if ((off > 0) && (odir->cur_name[0] == '\0')) {
        ret = fuse_reply_buf(req, NULL, 0);
        if (ret != 0)
            goto err;
        return;
    }

    priv = (struct fspriv *)(md->priv);

    buf = do_malloc(size);
    if (buf == NULL) {
        ret = errno;
        goto err;
    }

    opargs.req = req;

    opargs.be = priv->be;

    opargs.odir = odir;
    opargs.buf = buf;
    opargs.bufsize = size;
    opargs.off = off;

    ret = -do_back_end_op(priv, &do_read_entries, &opargs);
    if (ret != 0) {
        free(buf);
        goto err;
    }

    ret = fuse_reply_buf(req, buf, opargs.buflen);
    free(buf);
    if (ret != 0)
        goto err;

    return;

err:
    fuse_reply_err(req, ret);
}

static void
simplefs_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct open_dir *odir;

    (void)ino;

    odir = (struct open_dir *)(fi->fh);

    free(odir);

    fuse_reply_err(req, 0);
}

struct fuse_lowlevel_ops simplefs_ops = {
    .init       = &simplefs_init,
    .destroy    = &simplefs_destroy,
    .lookup     = &simplefs_lookup,
    .getattr    = &simplefs_getattr,
    .mkdir      = &simplefs_mkdir,
    .opendir    = &simplefs_opendir,
    .readdir    = &simplefs_readdir,
    .releasedir = &simplefs_releasedir
};

/* vi: set expandtab sw=4 ts=4: */
