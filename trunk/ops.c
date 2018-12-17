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
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/mount.h>

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

#define DB_PATHNAME "fs.db"

static void verror(int, const char *, va_list);

static void *worker_td(void *);

static int join_worker(struct fspriv *);

static void abort_init(struct mount_data *, int, const char *, ...);

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

    err = pthread_join(priv->worker_td, &retval);

    return err ? err : (intptr_t)retval;
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

static void
simplefs_init(void *userdata, struct fuse_conn_info *conn)
{
    int err;
    struct db_args args;
    struct fspriv *priv;
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

    err = back_end_open(&priv->be, &args);
    if (err) {
        if (err != -ENOENT)
            goto err3;
        err = back_end_create(&priv->be, FUSE_ROOT_ID, &args);
        if (err)
            goto err3;
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

struct fuse_lowlevel_ops simplefs_ops = {
    .init       = &simplefs_init,
    .destroy    = &simplefs_destroy
};

/* vi: set expandtab sw=4 ts=4: */
