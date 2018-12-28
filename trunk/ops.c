/*
 * ops.c
 */

#include "back_end.h"
#include "ops.h"
#include "simplefs.h"
#include "util.h"

#include <avl_tree.h>
#include <fifo.h>
#include <strings_ext.h>

#include <files/acc_ctl.h>

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
#include <time.h>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

struct ref_inodes {
    struct avl_tree *ref_inodes;
    pthread_mutex_t ref_inodes_mtx;
};

struct fspriv {
    struct back_end     *be;
    struct fifo         *queue;
    pthread_t           worker_td;
    struct ref_inodes   ref_inodes;
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
    uint32_t                num_ents;
} __attribute__((packed));

struct op_args {
    fuse_req_t          req;
    struct back_end     *be;
    struct ref_inodes   *ref_inodes;
    struct ref_ino      *refinop;
    fuse_ino_t          ino;
    fuse_ino_t          parent;
    const char          *name;
    char                *buf;
    off_t               off;
    struct db_key       k;
    struct db_obj_stat  s;
    struct stat         attr;
    /* lookup() */
    int                 inc_lookup_cnt;
    /* forget() */
    unsigned long       nlookup;
    /* setattr() */
    int                 to_set;
    /* mknod() */
    dev_t               rdev;
    /* mkdir() */
    mode_t              mode;
    /* rename() */
    fuse_ino_t          newparent;
    const char          *newname;
    /* read() */
    size_t              size;
    struct iovec        *iov;
    int                 count;
    /* readdir() */
    struct open_dir     *odir;
    size_t              bufsize;
    size_t              buflen;
};

struct open_dir {
    char        cur_name[NAME_MAX+1];
    fuse_ino_t  ino;
};

struct open_file {
    fuse_ino_t ino;
};

#define PG_SIZE (128 * 1024)

#define DB_PATHNAME "fs.db"

#define OP_RET_NONE INT_MAX

#define DB_OBJ_MAX_SIZE (sizeof(struct db_obj_stat))

#define NAME_CUR_DIR "."
#define NAME_PARENT_DIR ".."

#define CACHE_TIMEOUT 0.0
#define KEEP_CACHE_OPEN 1

static void verror(int, const char *, va_list);

static int uint64_cmp(uint64_t, uint64_t);

static int db_key_cmp(const void *, const void *, struct back_end_key_ctx *);

static void *worker_td(void *);
static int do_queue_op(struct fspriv *, int (*)(void *), void *);
static int join_worker(struct fspriv *);

static int dump_cb(const void *, const void *, size_t, void *);
static int dump_db(struct back_end *);

static int ref_inode_cmp(const void *, const void *, void *);

static uint64_t adj_refcnt(uint64_t *, int32_t);
static int get_next_ino(struct back_end *, fuse_ino_t *);
static int unref_inode(struct back_end *, struct ref_inodes *, struct ref_ino *,
                       int32_t, int32_t, int32_t);
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

static int truncate_file(struct back_end *, fuse_ino_t, size_t, size_t);
static int delete_file(struct back_end *, fuse_ino_t);

static void free_iov(struct iovec *, int);

static int fusermount_unmount(const char *);
static void abort_init(struct mount_data *, int, const char *, ...);

static int new_node(struct back_end *, struct ref_inodes *, fuse_ino_t,
                    const char *, uid_t, gid_t, mode_t, dev_t, struct stat *,
                    struct ref_ino **);

static int new_node_link(struct back_end *, struct ref_inodes *, fuse_ino_t,
                         fuse_ino_t, const char *, struct ref_ino **);
static int rem_node_link(struct back_end *, struct ref_inodes *, fuse_ino_t,
                         fuse_ino_t, const char *, struct ref_ino **);

static int new_dir(struct back_end *, struct ref_inodes *, fuse_ino_t,
                   const char *, uid_t, gid_t, mode_t, struct stat *,
                   struct ref_ino **);
static int rem_dir(struct back_end *, struct ref_inodes *, fuse_ino_t,
                   fuse_ino_t, const char *, int);

static int new_dir_link(struct back_end *, struct ref_inodes *, fuse_ino_t,
                        fuse_ino_t, const char *, struct ref_ino **);
static int rem_dir_link(struct back_end *, struct ref_inodes *, fuse_ino_t,
                        fuse_ino_t, const char *, struct ref_ino **);

static int do_look_up(void *);
static int do_setattr(void *);
static int do_forget(void *);
static int do_create_node(void *);
static int do_create_dir(void *);
static int do_remove_node_link(void *);
static int do_remove_dir(void *);
static int do_rename(void *);
static int do_create_node_link(void *);
static int do_read_entries(void *);
static int do_open(void *);
static int do_read(void *);
static int do_write(void *);
static int do_close(void *);

static void simplefs_init(void *, struct fuse_conn_info *);
static void simplefs_destroy(void *);
static void simplefs_lookup(fuse_req_t, fuse_ino_t, const char *);
static void simplefs_forget(fuse_req_t, fuse_ino_t, unsigned long);
static void simplefs_getattr(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void simplefs_setattr(fuse_req_t, fuse_ino_t, struct stat *, int,
                             struct fuse_file_info *);
static void simplefs_mknod(fuse_req_t, fuse_ino_t, const char *, mode_t, dev_t);
static void simplefs_mkdir(fuse_req_t, fuse_ino_t, const char *, mode_t);
static void simplefs_unlink(fuse_req_t, fuse_ino_t, const char *);
static void simplefs_rmdir(fuse_req_t, fuse_ino_t, const char *);
static void simplefs_rename(fuse_req_t, fuse_ino_t, const char *, fuse_ino_t,
                            const char *);
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
static void simplefs_releasedir(fuse_req_t, fuse_ino_t,
                                struct fuse_file_info *);
static void simplefs_access(fuse_req_t, fuse_ino_t, int);

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
    struct fspriv *priv;
    struct mount_data *md = (struct mount_data *)args;
    struct queue_elem *op;

    priv = md->priv;

    for (;;) {
        ret = fifo_get(priv->queue, &op);
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
        fprintf(stderr, "Page: node %" PRIu64 ", page %" PRIu64 ", size %zd\n",
                (uint64_t)(k->ino), (uint64_t)(k->pgno), datasize);
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
ref_inode_cmp(const void *k1, const void *k2, void *ctx)
{
    struct ref_ino *ino1 = *(struct ref_ino **)k1;
    struct ref_ino *ino2 = *(struct ref_ino **)k2;

    return uint64_cmp(ino1->ino, ino2->ino);
}

static uint64_t
adj_refcnt(uint64_t *refcnt, int32_t delta)
{
    if (delta != 0)
        *refcnt = (delta == -INT_MAX) ? 0 : (*refcnt + delta);

    return *refcnt;
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

static int
unref_inode(struct back_end *be, struct ref_inodes *ref_inodes,
            struct ref_ino *ino, int32_t nlink, int32_t nref, int32_t nlookup)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    uint64_t nlinkp, refcntp, nlookupp;

    k.type = TYPE_STAT;
    k.ino = ino->ino;
    ret = back_end_look_up(be, &k, NULL, &s);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    pthread_mutex_lock(&ref_inodes->ref_inodes_mtx);
    nlinkp = adj_refcnt(&ino->nlink, nlink);
    refcntp = adj_refcnt(&ino->refcnt, nref);
    nlookupp = adj_refcnt(&ino->nlookup, nlookup);
    pthread_mutex_unlock(&ref_inodes->ref_inodes_mtx);

    if ((nlinkp == 0) && (refcntp == 0) && (nlookupp == 0))
        return delete_file(be, ino->ino);

    if (nlink != 0) {
        s.st_nlink = (uint32_t)nlinkp;
        assert(s.st_ino == k.ino);
        return back_end_replace(be, &k, &s, sizeof(s));
    }

    return 0;
}

static int
free_ref_inodes_cb(const void *keyval, void *ctx)
{
    struct fspriv *priv = (struct fspriv *)ctx;
    struct ref_ino *ino = *(struct ref_ino **)keyval;

    unref_inode(priv->be, &priv->ref_inodes, ino, 0, -INT_MAX, -INT_MAX);

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
            ret = -errno;
            goto err1;
        }

        k.type = TYPE_STAT;
        k.ino = ino;
        ret = back_end_look_up(be, &k, NULL, &s);
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
truncate_file(struct back_end *be, fuse_ino_t ino, size_t oldsize,
              size_t newsize)
{
    int ret;
    size_t lastpgsz;
    struct db_key k;
    uint64_t i;
    uint64_t newnumpg, oldnumpg;

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

        ret = back_end_look_up(be, &k, NULL, buf);
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

    ret = back_end_look_up(be, &k, NULL, &s);
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

static int
fusermount_unmount(const char *name)
{
    int status;
    pid_t pid;

    pid = fork();
    if (pid == 0) {
        execlp("fusermount", "fusermount", "-u", name, NULL);
        abort();
    }
    if (pid == -1)
        return -errno;

    if (waitpid(pid, &status, 0) == -1)
        return -errno;

    if (!WIFEXITED(status))
        return -EIO;

    status = WEXITSTATUS(status);

    return (status == 0) ? 0 : -EIO;
}

static void
abort_init(struct mount_data *md, int err, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    verror(err, fmt, ap);
    va_end(ap);

    if (fusermount_unmount(md->mountpoint) == -1)
        abort();
}

static int
new_node(struct back_end *be, struct ref_inodes *ref_inodes, fuse_ino_t parent,
         const char *name, uid_t uid, gid_t gid, mode_t mode, dev_t rdev,
         struct stat *attr, struct ref_ino **inop)
{
    fuse_ino_t ino;
    int ret;
    struct db_key k;
    struct db_obj_stat ps, s;
    struct ref_ino *refinop[2];

    if ((mode & S_IFMT) == S_IFDIR)
        return -EINVAL;

    ret = back_end_trans_new(be);
    if (ret != 0)
        return ret;

    ret = get_next_ino(be, &ino);
    if (ret != 0)
        return ret;

    k.type = TYPE_STAT;
    k.ino = ino;

    s.st_dev = 64 * 1024;
    s.st_ino = ino;
    s.st_mode = mode & (S_IFMT | ALLPERMS);
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

    ret = new_node_link(be, ref_inodes, ino, parent, name, &refinop[0]);
    if (ret != 0)
        goto err1;

    if (ref_inodes != NULL) {
        ret = inc_refcnt(be, ref_inodes, ino, 0, 0, 1, &refinop[1]);
        if (ret != 0)
            goto err2;
    }

    k.ino = parent;

    ret = back_end_look_up(be, &k, NULL, &ps);
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

    ret = back_end_trans_commit(be);
    if (ret != 0)
        goto err3;

    if (attr != NULL)
        deserialize_stat(attr, &s);
    if (ref_inodes != NULL)
        *inop = refinop[1];

    return 0;

err3:
    dec_refcnt(ref_inodes, 0, 0, -1, refinop[1]);
err2:
    dec_refcnt(ref_inodes, -1, 0, 0, refinop[0]);
err1:
    back_end_trans_abort(be);
    return ret;
}

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

    k.type = TYPE_DIRENT;
    k.ino = newparent;
    strlcpy(k.name, newname, sizeof(k.name));

    de.ino = ino;

    ret = back_end_insert(be, &k, &de, sizeof(de));
    if (ret != 0)
        return ret;

    k.type = TYPE_STAT;
    k.ino = ino;

    ret = back_end_look_up(be, &k, NULL, &s);
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

static int
new_dir(struct back_end *be, struct ref_inodes *ref_inodes, fuse_ino_t parent,
        const char *name, uid_t uid, gid_t gid, mode_t mode, struct stat *attr,
        struct ref_ino **inop)
{
    fuse_ino_t ino;
    int ret;
    int rootdir = (parent == 0);
    struct db_key k;
    struct db_obj_stat s;
    struct ref_ino *refinop[4];

    ret = back_end_trans_new(be);
    if (ret != 0)
        return ret;

    if (rootdir)
        parent = ino = FUSE_ROOT_ID;
    else {
        ret = get_next_ino(be, &ino);
        if (ret != 0)
            return ret;
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

    if (ref_inodes != NULL) {
        ret = inc_refcnt(be, ref_inodes, ino, 0, 0, 1, &refinop[3]);
        if (ret != 0)
            goto err4;
    }

    if (!rootdir) {
        struct db_obj_stat ps;

        k.ino = parent;

        ret = back_end_look_up(be, &k, NULL, &ps);
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

    ret = back_end_trans_commit(be);
    if (ret != 0)
        goto err5;

    if (attr != NULL)
        deserialize_stat(attr, &s);
    if (ref_inodes != NULL)
        *inop = refinop[3];

    return 0;

err5:
    if (ref_inodes != NULL)
        dec_refcnt(ref_inodes, 0, 0, -1, refinop[3]);
err4:
    if (!rootdir)
        dec_refcnt(ref_inodes, -1, 0, 0, refinop[2]);
err3:
    dec_refcnt(ref_inodes, -1, 0, 0, refinop[1]);
err2:
    dec_refcnt(ref_inodes, -1, 0, 0, refinop[0]);
err1:
    back_end_trans_abort(be);
    return ret;
}

static int
rem_dir(struct back_end *be, struct ref_inodes *ref_inodes, fuse_ino_t ino,
        fuse_ino_t parent, const char *name, int notrans)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct ref_ino *refinop[3];

    k.type = TYPE_STAT;
    k.ino = ino;
    ret = back_end_look_up(be, &k, NULL, &s);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;
    if (s.num_ents != 0)
        return -ENOTEMPTY;

    k.ino = parent;
    ret = back_end_look_up(be, &k, NULL, &s);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    ret = set_ref_inode_nodelete(be, ref_inodes, ino, 1);
    if (ret != 0)
        return ret;

    if (!notrans) {
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
    set_ref_inode_nodelete(be, ref_inodes, ino, 0);
    return ret;
}

static int
new_dir_link(struct back_end *be, struct ref_inodes *ref_inodes, fuse_ino_t ino,
             fuse_ino_t newparent, const char *newname, struct ref_ino **inop)
{
    int ret;
    struct db_key k;
    struct db_obj_dirent de;
    struct db_obj_stat s;
    struct ref_ino *refinop;

    k.type = TYPE_DIRENT;
    k.ino = newparent;
    strlcpy(k.name, newname, sizeof(k.name));

    de.ino = ino;

    ret = back_end_insert(be, &k, &de, sizeof(de));
    if (ret != 0)
        return ret;

    k.type = TYPE_STAT;
    k.ino = ino;

    ret = back_end_look_up(be, &k, NULL, &s);
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

static int
rem_node_link(struct back_end *be, struct ref_inodes *ref_inodes,
              fuse_ino_t ino, fuse_ino_t parent, const char *name,
              struct ref_ino **inop)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct ref_ino refino, *refinop;

    k.type = TYPE_DIRENT;
    k.ino = parent;
    strlcpy(k.name, name, sizeof(k.name));

    ret = back_end_delete(be, &k);
    if (ret != 0)
        return ret;

    k.type = TYPE_STAT;
    k.ino = ino;

    ret = back_end_look_up(be, &k, NULL, &s);
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
    ret = unref_inode(be, ref_inodes, refinop, -1, 0, 0);
    if (ret == 0)
        *inop = refinop;

    return ret;
}

static int
rem_dir_link(struct back_end *be, struct ref_inodes *ref_inodes, fuse_ino_t ino,
             fuse_ino_t parent, const char *name, struct ref_ino **inop)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct ref_ino refino, *refinop;

    k.type = TYPE_DIRENT;
    k.ino = parent;
    strlcpy(k.name, name, sizeof(k.name));

    ret = back_end_delete(be, &k);
    if (ret != 0)
        return ret;

    k.type = TYPE_STAT;
    k.ino = ino;

    ret = back_end_look_up(be, &k, NULL, &s);
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
    ret = unref_inode(be, ref_inodes, refinop, -1, 0, 0);
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
        ret = back_end_look_up(opargs->be, &opargs->k, NULL, &de);
        if (ret != 1)
            return ret;

        k.type = TYPE_STAT;
        k.ino = de.ino;
        ret = back_end_look_up(opargs->be, &k, NULL, &opargs->s);
        if (ret != 1)
            return ret;

        break;
    case TYPE_STAT:
        ret = back_end_look_up(opargs->be, &opargs->k, NULL, &opargs->s);
        if (ret != 1)
            return ret;

        break;
    default:
        return -EIO;
    }

    if (opargs->inc_lookup_cnt) {
        ret = inc_refcnt(opargs->be, opargs->ref_inodes, opargs->s.st_ino, 0,
                         0, 1, &opargs->refinop);
        if (ret != 0)
            return ret;
    }

    return 1;
}

static int
do_setattr(void *args)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = (struct op_args *)args;

    k.type = TYPE_STAT;
    k.ino = opargs->ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &s);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    if (opargs->to_set & FUSE_SET_ATTR_SIZE) {
        if (!S_ISREG(s.st_mode))
            return -EINVAL;
        ret = truncate_file(opargs->be, opargs->ino, s.st_size,
                            opargs->attr.st_size);
        if (ret != 0)
            return ret;
        s.st_size = opargs->attr.st_size;
    }

    if (opargs->to_set & FUSE_SET_ATTR_ATIME_NOW)
        do_set_ts(&s.st_atim, NULL);
    if (opargs->to_set & FUSE_SET_ATTR_MTIME_NOW)
        do_set_ts(&s.st_mtim, NULL);
    if (opargs->to_set & FUSE_SET_ATTR_ATIME)
        do_set_ts(&s.st_atim, &opargs->attr.st_atim);
    if (opargs->to_set & FUSE_SET_ATTR_MTIME)
        do_set_ts(&s.st_mtim, &opargs->attr.st_mtim);

    ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
    if (ret != 0)
        return ret;

    deserialize_stat(&opargs->attr, &s);

    return 0;
}

static int
do_forget(void *args)
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

    return unref_inode(opargs->be, opargs->ref_inodes, refinop, 0, 0,
                       -(opargs->nlookup));
}

static int
do_create_node(void *args)
{
    int err;
    struct fuse_context *ctx = fuse_get_context();
    struct op_args *opargs = (struct op_args *)args;

    err = new_node(opargs->be, opargs->ref_inodes, opargs->ino, opargs->name,
                   ctx->uid, ctx->gid, opargs->mode & ~(ctx->umask),
                   opargs->rdev, &opargs->attr, &opargs->refinop);
    if (err)
        return err;

    dump_db(opargs->be);

    return 0;
}

static int
do_create_dir(void *args)
{
    int err;
    struct fuse_context *ctx = fuse_get_context();
    struct op_args *opargs = (struct op_args *)args;

    err = new_dir(opargs->be, opargs->ref_inodes, opargs->ino, opargs->name,
                  ctx->uid, ctx->gid, opargs->mode & ~(ctx->umask),
                  &opargs->attr, &opargs->refinop);
    if (err)
        return err;

    dump_db(opargs->be);

    return 0;
}

static int
do_remove_node_link(void *args)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = (struct op_args *)args;
    struct ref_ino *refinop;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    k.type = TYPE_STAT;
    k.ino = opargs->parent;

    ret = back_end_look_up(opargs->be, &k, NULL, &s);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err;
    }

    ret = rem_node_link(opargs->be, opargs->ref_inodes, opargs->ino,
                        opargs->parent, opargs->name, &refinop);
    if (ret != 0)
        goto err;

    --(s.num_ents);

    ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
    if (ret != 0)
        goto err;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err;

    dump_db(opargs->be);

    return 0;

err:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_remove_dir(void *args)
{
    int err;
    struct op_args *opargs = (struct op_args *)args;

    err = rem_dir(opargs->be, opargs->ref_inodes, opargs->ino, opargs->parent,
                  opargs->name, 0);
    if (err)
        return err;

    dump_db(opargs->be);

    return 0;
}

static int
do_rename(void *args)
{
    int ret;
    struct db_key k;
    struct db_obj_dirent dde, sde;
    struct db_obj_stat ds, ss;
    struct op_args *opargs = (struct op_args *)args;
    struct ref_ino *refinop[2];

    k.type = TYPE_DIRENT;
    k.ino = opargs->parent;
    strlcpy(k.name, opargs->name, sizeof(k.name));

    ret = back_end_look_up(opargs->be, &k, NULL, &sde);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    k.type = TYPE_STAT;
    k.ino = sde.ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &ss);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    k.type = TYPE_DIRENT;
    k.ino = opargs->newparent;
    strlcpy(k.name, opargs->newname, sizeof(k.name));

    ret = back_end_look_up(opargs->be, &k, NULL, &dde);
    if (ret != 0) {
        if (ret != 1)
            goto err1;

        k.type = TYPE_STAT;
        k.ino = dde.ino;

        ret = back_end_look_up(opargs->be, &k, NULL, &ds);
        if (ret != 1) {
            if (ret == 0)
                ret = -ENOENT;
            goto err1;
        }

        /* delete existing link or directory */

        if (!S_ISDIR(ss.st_mode) && S_ISDIR(ds.st_mode)) {
            ret = -EISDIR;
            goto err1;
        }
        if (S_ISDIR(ss.st_mode) && !S_ISDIR(ds.st_mode)) {
            ret = -ENOTDIR;
            goto err1;
        }

        if (!S_ISDIR(ds.st_mode)) {
            ret = -ENOSYS;
            goto err1;
        }
        ret = rem_dir(opargs->be, opargs->ref_inodes, ds.st_ino,
                      opargs->newparent, opargs->newname, 1);
        if (ret != 0)
            goto err1;
    }

    ret = new_dir_link(opargs->be, opargs->ref_inodes, ss.st_ino,
                       opargs->newparent, opargs->newname, &refinop[0]);
    if (ret != 0)
        goto err1;

    ret = rem_dir_link(opargs->be, opargs->ref_inodes, ss.st_ino,
                       opargs->parent, opargs->name, &refinop[1]);
    if (ret != 0)
        goto err2;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err3;

    return 0;

err3:
    inc_refcnt(opargs->be, opargs->ref_inodes, ss.st_ino, 1, 0, 0, &refinop[1]);
err2:
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, refinop[0]);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
}

static int
do_create_node_link(void *args)
{
    int ret;
    struct db_key k;
    struct op_args *opargs = (struct op_args *)args;
    struct ref_ino *refinop;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    ret = new_node_link(opargs->be, opargs->ref_inodes, opargs->ino,
                        opargs->newparent, opargs->newname, &refinop);
    if (ret != 0)
        goto err1;

    ret = inc_refcnt(opargs->be, opargs->ref_inodes, opargs->ino, 0, 0, 1,
                     &opargs->refinop);
    if (ret != 0)
        goto err2;

    ret = back_end_trans_commit(opargs->be);
    if (ret != 0)
        goto err3;

    k.type = TYPE_STAT;
    k.ino = opargs->ino;
    ret = back_end_look_up(opargs->be, &k, NULL, &opargs->s);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err3;
    }

    return 0;

err3:
    dec_refcnt(opargs->ref_inodes, 0, 0, -1, opargs->refinop);
err2:
    dec_refcnt(opargs->ref_inodes, -1, 0, 0, refinop);
err1:
    back_end_trans_abort(opargs->be);
    return ret;
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

static int
do_open(void *args)
{
    int ret;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = (struct op_args *)args;

    k.type = TYPE_STAT;
    k.ino = opargs->ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &s);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    return inc_refcnt(opargs->be, opargs->ref_inodes, opargs->ino, 0, 1, 0,
                      &opargs->refinop);
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

    ret = back_end_look_up(opargs->be, &k, NULL, &s);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    firstpgidx = opargs->off / PG_SIZE;
    lastpgidx = (MIN(opargs->off + opargs->size, s.st_size) - 1) / PG_SIZE;
    count = lastpgidx - firstpgidx + 1;

    iov = do_calloc(count, sizeof(*iov));
    if (iov == NULL)
        return -errno;

    k.type = TYPE_PAGE;

    off = opargs->off;
    size = opargs->size;
    iovsz = 0;
    for (i = 0; i < count; i++) {
        char buf[PG_SIZE];
        size_t pgoff;
        size_t sz;

        k.pgno = off / PG_SIZE;

        pgoff = off - (k.pgno * PG_SIZE);

        sz = MIN((k.pgno + 1) * PG_SIZE, s.st_size) - off;
        if (sz > size)
            sz = size;

        iov[i].iov_base = do_malloc(sz);
        if (iov[i].iov_base == NULL) {
            ret = -errno;
            goto err;
        }
        ++iovsz;

        ret = back_end_look_up(opargs->be, &k, NULL, buf);
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

    opargs->iov = iov;
    opargs->count = count;

    return 0;

err:
    free_iov(iov, iovsz);
    return ret;
}

static int
do_write(void *args)
{
    int ret;
    off_t off;
    size_t size;
    struct db_key k;
    struct db_obj_stat s;
    struct op_args *opargs = (struct op_args *)args;

    k.type = TYPE_STAT;
    k.ino = opargs->ino;

    ret = back_end_look_up(opargs->be, &k, NULL, &s);
    if (ret != 1)
        return (ret == 0) ? -ENOENT : ret;

    ret = back_end_trans_new(opargs->be);
    if (ret != 0)
        return ret;

    k.type = TYPE_PAGE;

    off = opargs->off;
    size = opargs->size;
    while (size > 0) {
        char buf[PG_SIZE];
        size_t pgoff;
        size_t sz;

        k.pgno = off / PG_SIZE;

        pgoff = off - k.pgno * PG_SIZE;

        sz = (k.pgno + 1) * PG_SIZE - off;
        if (sz > size)
            sz = size;

        ret = back_end_look_up(opargs->be, &k, NULL, buf);
        if (ret != 1) {
            if (ret != 0)
                return ret;

            memcpy(buf + pgoff, opargs->buf + opargs->size - sz, sz);

            ret = back_end_insert(opargs->be, &k, buf, pgoff + sz);
        } else {
            memcpy(buf + pgoff, opargs->buf + opargs->size - sz, sz);

            ret = back_end_replace(opargs->be, &k, buf, sizeof(buf));
        }
        if (ret != 0)
            return ret;

        off += sz;
        size -= sz;
    }

    if (off > s.st_size) {
        s.st_size = off;

        k.type = TYPE_STAT;

        ret = back_end_replace(opargs->be, &k, &s, sizeof(s));
        if (ret != 0)
            return ret;
    }

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

    return unref_inode(opargs->be, opargs->ref_inodes, refinop, 0, -1, 0);
}

static void
simplefs_init(void *userdata, struct fuse_conn_info *conn)
{
    int err;
    struct db_args args;
    struct fspriv *priv;
    struct fuse_context *ctx = fuse_get_context();
    struct mount_data *md = (struct mount_data *)userdata;
    struct ref_ino *refinop;

    conn->want = FUSE_CAP_ATOMIC_O_TRUNC | FUSE_CAP_EXPORT_SUPPORT;

    priv = do_malloc(sizeof(*priv));
    if (priv == NULL) {
        err = -errno;
        goto err1;
    }

    err = fifo_new(&priv->queue, sizeof(struct queue_elem *), 1024);
    if (err)
        goto err2;

    args.db_pathname = DB_PATHNAME;
    args.db_mode = ACC_MODE_DEFAULT;

    err = avl_tree_new(&priv->ref_inodes.ref_inodes, sizeof(struct ref_ino *),
                       &ref_inode_cmp, 0, NULL, NULL, NULL);
    if (err)
        goto err3;
    err = -pthread_mutex_init(&priv->ref_inodes.ref_inodes_mtx, NULL);
    if (err)
        goto err4;

    err = back_end_open(&priv->be, sizeof(struct db_key), &db_key_cmp, &args);
    if (err) {
        struct db_key k;
        struct db_obj_header hdr;

        if (err != -ENOENT)
            goto err5;

        err = back_end_create(&priv->be, sizeof(struct db_key), &db_key_cmp,
                              &args);
        if (err)
            goto err5;

        k.type = TYPE_HEADER;
        hdr.next_ino = FUSE_ROOT_ID + 1;
        err = back_end_insert(priv->be, &k, &hdr, sizeof(hdr));
        if (err)
            goto err6;

        /* create root directory */
        err = new_dir(priv->be, &priv->ref_inodes, 0, NULL, ctx->uid, ctx->gid,
                      ACCESSPERMS & ~(ctx->umask), NULL, &refinop);
        if (err)
            goto err6;
    }

    md->priv = priv;

    err = -pthread_create(&priv->worker_td, NULL, &worker_td, md);
    if (err)
        goto err6;

    return;

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
    abort_init(md, -err, "Error mounting FUSE file system");
}

static void
simplefs_destroy(void *userdata)
{
    avl_tree_walk_ctx_t wctx = NULL;
    struct fspriv *priv;
    struct mount_data *md = (struct mount_data *)userdata;

    priv = md->priv;

    join_worker(priv);

    avl_tree_walk(priv->ref_inodes.ref_inodes, NULL, &free_ref_inodes_cb, priv,
                  &wctx);
    avl_tree_free(priv->ref_inodes.ref_inodes);
    pthread_mutex_destroy(&priv->ref_inodes.ref_inodes_mtx);

    back_end_close(priv->be);

    fifo_free(priv->queue);

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

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.k.type = TYPE_DIRENT;
    opargs.k.ino = parent;
    strlcpy(opargs.k.name, name, sizeof(opargs.k.name));

    opargs.inc_lookup_cnt = 1;

    ret = do_queue_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        if (ret != 0)
            goto err;
        e.ino = 0;
    } else {
        e.ino = opargs.s.st_ino;
        deserialize_stat(&e.attr, &opargs.s);
    }
    e.generation = 1;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;

    ret = fuse_reply_entry(req, &e);
    if (ret != 0) {
        if (e.ino != 0)
            dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop);
        goto err;
    }

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_forget(fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;
    opargs.nlookup = nlookup;

    do_queue_op(priv, &do_forget, &opargs);

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

    opargs.inc_lookup_cnt = 0;

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
    if (ret != 0)
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

    (void)fi;

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;
    opargs.attr = *attr;
    opargs.to_set = to_set;

    ret = do_queue_op(priv, &do_setattr, &opargs);
    if (ret != 0)
        goto err;

    ret = fuse_reply_attr(req, &opargs.attr, CACHE_TIMEOUT);
    if (ret != 0)
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

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = parent;
    opargs.name = name;
    opargs.mode = mode;
    opargs.rdev = rdev;

    ret = do_queue_op(priv, &do_create_node, &opargs);
    if (ret != 0)
        goto err;

    e.ino = opargs.attr.st_ino;
    e.generation = 1;
    e.attr = opargs.attr;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;
    ret = fuse_reply_entry(req, &e);
    if (ret != 0) {
        dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop);
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

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = parent;
    opargs.name = name;
    opargs.mode = mode;

    ret = do_queue_op(priv, &do_create_dir, &opargs);
    if (ret != 0)
        goto err;

    e.ino = opargs.attr.st_ino;
    e.generation = 1;
    e.attr = opargs.attr;
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;
    ret = fuse_reply_entry(req, &e);
    if (ret != 0) {
        dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop);
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

    opargs.inc_lookup_cnt = 0;

    ret = do_queue_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err;
    }

    opargs.parent = parent;
    opargs.ino = opargs.s.st_ino;
    opargs.name = name;

    ret = do_queue_op(priv, &do_remove_node_link, &opargs);
    if (ret != 0)
        goto err;

    ret = fuse_reply_err(req, 0);
    if (ret != 0)
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

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.k.type = TYPE_DIRENT;
    opargs.k.ino = parent;
    strlcpy(opargs.k.name, name, sizeof(opargs.k.name));

    opargs.inc_lookup_cnt = 0;

    ret = do_queue_op(priv, &do_look_up, &opargs);
    if (ret != 1) {
        if (ret == 0)
            ret = -ENOENT;
        goto err;
    }

    opargs.parent = parent;
    opargs.ino = opargs.s.st_ino;
    opargs.name = name;

    ret = do_queue_op(priv, &do_remove_dir, &opargs);
    if (ret != 0)
        goto err;

    ret = fuse_reply_err(req, 0);
    if (ret != 0)
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
                fuse_ino_t newparent, const char *newname)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.parent = parent;
    opargs.name = name;
    opargs.newparent = newparent;
    opargs.newname = newname;

    ret = do_queue_op(priv, &do_rename, &opargs);
    if (ret != 0)
        goto err;

    ret = fuse_reply_err(req, 0);
    if (ret != 0)
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
    opargs.newparent = newparent;
    opargs.newname = newname;

    ret = do_queue_op(priv, &do_create_node_link, &opargs);
    if (ret != 0)
        goto err;

    e.ino = opargs.s.st_ino;
    e.generation = 1;
    deserialize_stat(&e.attr, &opargs.s);
    e.attr_timeout = e.entry_timeout = CACHE_TIMEOUT;
    ret = fuse_reply_entry(req, &e);
    if (ret != 0) {
        dec_refcnt(&priv->ref_inodes, 0, 0, -1, opargs.refinop);
        goto err;
    }

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;
    struct open_file *ofile;

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    ret = do_queue_op(priv, &do_open, &opargs);
    if (ret != 0)
        goto err1;

    ofile = do_malloc(sizeof(*ofile));
    if (ofile == NULL) {
        ret = -errno;
        goto err2;
    }

    ofile->ino = ino;

    fi->fh = (uintptr_t)ofile;
    fi->keep_cache = KEEP_CACHE_OPEN;

    ret = -fuse_reply_open(req, fi);
    if (ret != 0)
        goto err3;

    return;

err3:
    free(ofile);
err2:
    do_queue_op(priv, &do_close, &opargs);
err1:
    fuse_reply_err(req, -ret);
}

static void
simplefs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
              struct fuse_file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;

    (void)fi;

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.size = size;
    opargs.off = off;

    ret = do_queue_op(priv, &do_read, &opargs);
    if (ret != 0)
        goto err;

    ret = fuse_reply_iov(req, opargs.iov, opargs.count);
    free_iov(opargs.iov, opargs.count);
    if (ret != 0)
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

    (void)fi;

    priv = md->priv;

    opargs.be = priv->be;

    opargs.ino = ino;

    opargs.buf = (char *)buf;
    opargs.size = size;
    opargs.off = off;

    ret = do_queue_op(priv, &do_write, &opargs);
    if (ret != 0)
        goto err;

    ret = fuse_reply_write(req, size);
    if (ret != 0)
        goto err;

    return;

err:
    fuse_reply_err(req, -ret);
}

static void
simplefs_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    int ret;

    (void)ino;
    (void)fi;

    ret = fuse_reply_err(req, 0);
    if (ret != 0)
        fuse_reply_err(req, -ret);
}

static void
simplefs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    int ret;
    struct fspriv *priv;
    struct mount_data *md = fuse_req_userdata(req);
    struct op_args opargs;
    struct open_dir *odir;

    priv = md->priv;

    opargs.be = priv->be;
    opargs.ref_inodes = &priv->ref_inodes;

    opargs.ino = ino;

    ret = do_queue_op(priv, &do_open, &opargs);
    if (ret != 0)
        goto err1;

    odir = do_malloc(sizeof(*odir));
    if (odir == NULL) {
        ret = -errno;
        goto err2;
    }

    odir->ino = ino;
    odir->cur_name[0] = '\0';

    fi->fh = (uintptr_t)odir;
    fi->keep_cache = KEEP_CACHE_OPEN;

    ret = -fuse_reply_open(req, fi);
    if (ret != 0)
        goto err3;

    return;

err3:
    free(odir);
err2:
    do_queue_op(priv, &do_close, &opargs);
err1:
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

    if ((off > 0) && (odir->cur_name[0] == '\0')) {
        ret = fuse_reply_buf(req, NULL, 0);
        if (ret != 0)
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

    opargs.odir = odir;
    opargs.buf = buf;
    opargs.bufsize = size;
    opargs.off = off;

    ret = do_queue_op(priv, &do_read_entries, &opargs);
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
simplefs_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
    int err;

    (void)ino;
    (void)mask;

    err = fuse_reply_err(req, 0);
    if (err)
        fuse_reply_err(req, -err);
}

struct fuse_lowlevel_ops simplefs_ops = {
    .init       = &simplefs_init,
    .destroy    = &simplefs_destroy,
    .lookup     = &simplefs_lookup,
    .forget     = &simplefs_forget,
    .getattr    = &simplefs_getattr,
    .setattr    = &simplefs_setattr,
    .mknod      = &simplefs_mknod,
    .mkdir      = &simplefs_mkdir,
    .unlink     = &simplefs_unlink,
    .rmdir      = &simplefs_rmdir,
    .rename     = &simplefs_rename,
    .link       = &simplefs_link,
    .open       = &simplefs_open,
    .read       = &simplefs_read,
    .write      = &simplefs_write,
    .flush      = &simplefs_flush,
    .release    = &simplefs_release,
    .opendir    = &simplefs_opendir,
    .readdir    = &simplefs_readdir,
    .releasedir = &simplefs_releasedir,
    .access     = &simplefs_access
};

/* vi: set expandtab sw=4 ts=4: */
