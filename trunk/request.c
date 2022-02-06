/*
 * request.c
 */

#include "common.h"
#include "ops.h"
#include "request.h"
#include "util.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fuse.h>
#include <fuse_lowlevel.h>

struct session {
    void                    *sctx;
    const struct sess_ops   *sess_ops;
};

struct request_ctx {
    void                        *rctx;
    const struct request_ops    *req_ops;
    const struct reply_ops      *reply_ops;
    struct session              sess;
};

struct request {
    struct request_ctx  *ctx;
    void                *req;
};

struct request_fuse {
    fuse_req_t              req;
    struct ctx              ctx;
    struct fuse_file_info   *fi;
};

#define REQUEST(op, ...) \
    do { \
        struct request r = {.ctx = ctx, .req = req}; \
        (*((ctx)->req_ops->op))(&r, ##__VA_ARGS__); \
    } while (0);

#define _REQUEST_FUSE(nm, r, filei) \
    struct request_fuse nm = {.req = (r), .fi = (filei)}

#define REQUEST_FUSE(nm) _REQUEST_FUSE(nm, req, fi)
#define REQUEST_FUSE_NO_FI(nm) _REQUEST_FUSE(nm, req, NULL)

static void init_fuse_entry_param(struct fuse_entry_param *,
                                  const struct entry_param *);

static void init_ctx(struct ctx *, const struct fuse_ctx *);

static void init_file_info(struct file_info *, const struct fuse_file_info *);
static void set_fuse_file_info(struct fuse_file_info *,
                               const struct file_info *);

static void request_fuse_init(void *, struct fuse_conn_info *);
static void request_fuse_destroy(void *);
static void request_fuse_lookup(fuse_req_t, fuse_ino_t, const char *);
#if FUSE_USE_VERSION == 32
static void request_fuse_forget(fuse_req_t, fuse_ino_t, uint64_t);
#else
static void request_fuse_forget(fuse_req_t, fuse_ino_t, unsigned long);
#endif
static void request_fuse_getattr(fuse_req_t, fuse_ino_t,
                                 struct fuse_file_info *);
static void request_fuse_setattr(fuse_req_t, fuse_ino_t, struct stat *, int,
                                 struct fuse_file_info *);
static void request_fuse_readlink(fuse_req_t, fuse_ino_t);
static void request_fuse_mknod(fuse_req_t, fuse_ino_t, const char *, mode_t,
                               dev_t);
static void request_fuse_mkdir(fuse_req_t, fuse_ino_t, const char *, mode_t);
static void request_fuse_unlink(fuse_req_t, fuse_ino_t, const char *);
static void request_fuse_rmdir(fuse_req_t, fuse_ino_t, const char *);
static void request_fuse_symlink(fuse_req_t, const char *, fuse_ino_t,
                                 const char *);
#if FUSE_USE_VERSION == 32
static void request_fuse_rename(fuse_req_t, fuse_ino_t, const char *,
                                fuse_ino_t, const char *, unsigned int);
#else
static void request_fuse_rename(fuse_req_t, fuse_ino_t, const char *,
                                fuse_ino_t, const char *);
#endif
static void request_fuse_link(fuse_req_t, fuse_ino_t, fuse_ino_t, const char *);
static void request_fuse_open(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void request_fuse_read(fuse_req_t, fuse_ino_t, size_t, off_t,
                              struct fuse_file_info *);
static void request_fuse_write(fuse_req_t, fuse_ino_t, const char *, size_t,
                               off_t, struct fuse_file_info *);
static void request_fuse_flush(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void request_fuse_opendir(fuse_req_t, fuse_ino_t,
                                 struct fuse_file_info *);
static void request_fuse_readdir(fuse_req_t, fuse_ino_t, size_t, off_t,
                                 struct fuse_file_info *);
static void request_fuse_release(fuse_req_t, fuse_ino_t,
                                 struct fuse_file_info *);
static void request_fuse_fsync(fuse_req_t, fuse_ino_t, int,
                               struct fuse_file_info *);
static void request_fuse_releasedir(fuse_req_t, fuse_ino_t,
                                    struct fuse_file_info *);
static void request_fuse_fsyncdir(fuse_req_t, fuse_ino_t, int,
                                  struct fuse_file_info *);
static void request_fuse_statfs(fuse_req_t, fuse_ino_t);
#ifdef __APPLE__
static void request_fuse_setxattr(fuse_req_t, fuse_ino_t, const char *,
                                  const char *, size_t, int, uint32_t);
static void request_fuse_getxattr(fuse_req_t, fuse_ino_t, const char *, size_t,
                                  uint32_t);
#else
static void request_fuse_setxattr(fuse_req_t, fuse_ino_t, const char *,
                                  const char *, size_t, int);
static void request_fuse_getxattr(fuse_req_t, fuse_ino_t, const char *, size_t);
#endif
static void request_fuse_listxattr(fuse_req_t, fuse_ino_t, size_t);
static void request_fuse_removexattr(fuse_req_t, fuse_ino_t, const char *);
static void request_fuse_access(fuse_req_t, fuse_ino_t, int);
static void request_fuse_create(fuse_req_t, fuse_ino_t, const char *, mode_t,
                                struct fuse_file_info *);
static void request_fuse_fallocate(fuse_req_t, fuse_ino_t, int, off_t, off_t,
                                   struct fuse_file_info *);

static int reply_fuse_err(void *, int);
static void reply_fuse_none(void *);
static int reply_fuse_entry(void *, const struct entry_param *);
static int reply_fuse_create(void *, const struct entry_param *,
                             const struct file_info *);
static int reply_fuse_attr(void *, const struct stat *, double);
static int reply_fuse_readlink(void *, const char *);
static int reply_fuse_open(void *, const struct file_info *);
static int reply_fuse_write(void *, size_t);
static int reply_fuse_buf(void *, const char *, size_t);
static int reply_fuse_iov(void *, const struct iovec *, int);
static int reply_fuse_statfs(void *, const struct statvfs *);
static int reply_fuse_xattr(void *, size_t);

static size_t add_direntry_fuse(void *, char *, size_t, const char *,
                                const struct stat *, off_t);

int
request_new(struct request_ctx **ctx, const struct request_ops *req_ops,
            const struct reply_ops *reply_ops, void *rctx,
            const struct sess_ops *sess_ops, void *sctx)
{
    int err;
    struct request_ctx *ret;

    if (oemalloc(&ret) == NULL)
        return MINUS_ERRNO;

    if (req_ops->new != NULL) {
        err = (*(req_ops->new))(rctx);
        if (err) {
            free(ret);
            return err;
        }
    }

    ret->rctx = rctx;
    ret->req_ops = req_ops;
    ret->reply_ops = reply_ops;

    ret->sess.sctx = sctx;
    ret->sess.sess_ops = sess_ops;

    *ctx = ret;
    return 0;
}

void
request_end(struct request_ctx *ctx)
{
    if (ctx->req_ops->end != NULL)
        (*(ctx->req_ops->end))(ctx->rctx);
}

int
request_init_prepare(struct request_ctx *ctx, inum_t root_id)
{
    return (*(ctx->req_ops->init_prepare))(ctx->rctx, &ctx->sess, root_id);
}

void
request_init(struct request_ctx *ctx, inum_t root_id)
{
    if (ctx->req_ops->init != NULL)
        (*(ctx->req_ops->init))(ctx->rctx, &ctx->sess, root_id);
}

void
request_destroy(struct request_ctx *ctx)
{
    if (ctx->req_ops->destroy != NULL)
        (*(ctx->req_ops->destroy))(ctx->rctx);
}

int
request_destroy_finish(struct request_ctx *ctx)
{
    return (*(ctx->req_ops->destroy_finish))(ctx->rctx);
}

void
request_lookup(struct request_ctx *ctx, void *req, inum_t parent,
               const char *name)
{
    REQUEST(lookup, parent, name);
}

void
request_forget(struct request_ctx *ctx, void *req, inum_t ino, uint64_t nlookup)
{
    REQUEST(forget, ino, nlookup);
}

void
request_getattr(struct request_ctx *ctx, void *req, inum_t ino,
                struct file_info *fi)
{
    REQUEST(getattr, ino, fi);
}

void
request_setattr(struct request_ctx *ctx, void *req, inum_t ino,
                struct stat *attr, int to_set, struct file_info *fi)
{
    REQUEST(setattr, ino, attr, to_set, fi);
}

void
request_readlink(struct request_ctx *ctx, void *req, inum_t ino)
{
    REQUEST(readlink, ino);
}

void
request_mknod(struct request_ctx *ctx, void *req, inum_t parent,
              const char *name, mode_t mode, dev_t rdev)
{
    REQUEST(mknod, parent, name, mode, rdev);
}

void
request_mkdir(struct request_ctx *ctx, void *req, inum_t parent,
              const char *name, mode_t mode)
{
    REQUEST(mkdir, parent, name, mode);
}

void
request_unlink(struct request_ctx *ctx, void *req, inum_t parent,
               const char *name)
{
    REQUEST(unlink, parent, name);
}

void
request_rmdir(struct request_ctx *ctx, void *req, inum_t parent,
              const char *name)
{
    REQUEST(rmdir, parent, name);
}

void
request_symlink(struct request_ctx *ctx, void *req, const char *link,
                inum_t parent, const char *name)
{
    REQUEST(symlink, link, parent, name);
}

void
request_rename(struct request_ctx *ctx, void *req, inum_t parent,
               const char *name, inum_t newparent, const char *newname)
{
    REQUEST(rename, parent, name, newparent, newname);
}

void
request_link(struct request_ctx *ctx, void *req, inum_t ino, inum_t newparent,
             const char *newname)
{
    REQUEST(link, ino, newparent, newname);
}

void
request_open(struct request_ctx *ctx, void *req, inum_t ino,
             struct file_info *fi)
{
    REQUEST(open, ino, fi);
}

void
request_read(struct request_ctx *ctx, void *req, inum_t ino, size_t size,
             off_t off, struct file_info *fi)
{
    REQUEST(read, ino, size, off, fi);
}

void
request_write(struct request_ctx *ctx, void *req, inum_t ino, const char *buf,
              size_t size, off_t off, struct file_info *fi)
{
    REQUEST(write, ino, buf, size, off, fi);
}

void
request_flush(struct request_ctx *ctx, void *req, inum_t ino,
              struct file_info *fi)
{
    REQUEST(flush, ino, fi);
}

void
request_opendir(struct request_ctx *ctx, void *req, inum_t ino,
                struct file_info *fi)
{
    REQUEST(opendir, ino, fi);
}

void
request_readdir(struct request_ctx *ctx, void *req, inum_t ino, size_t size,
                off_t off, struct file_info *fi)
{
    REQUEST(readdir, ino, size, off, fi);
}

void
request_release(struct request_ctx *ctx, void *req, inum_t ino,
                struct file_info *fi)
{
    REQUEST(release, ino, fi);
}

void
request_fsync(struct request_ctx *ctx, void *req, inum_t ino, int datasync,
              struct file_info *fi)
{
    REQUEST(fsync, ino, datasync, fi);
}

void
request_releasedir(struct request_ctx *ctx, void *req, inum_t ino,
                   struct file_info *fi)
{
    REQUEST(releasedir, ino, fi);
}

void
request_fsyncdir(struct request_ctx *ctx, void *req, inum_t ino, int datasync,
                 struct file_info *fi)
{
    REQUEST(fsyncdir, ino, datasync, fi);
}

void
request_statfs(struct request_ctx *ctx, void *req, inum_t ino)
{
    REQUEST(statfs, ino);
}

void
request_setxattr(struct request_ctx *ctx, void *req, inum_t ino,
                 const char *name, const char *value, size_t size, int flags)
{
    REQUEST(setxattr, ino, name, value, size, flags);
}

void
request_getxattr(struct request_ctx *ctx, void *req, inum_t ino,
                 const char *name, size_t size)
{
    REQUEST(getxattr, ino, name, size);
}

void
request_listxattr(struct request_ctx *ctx, void *req, inum_t ino, size_t size)
{
    REQUEST(listxattr, ino, size);
}

void
request_removexattr(struct request_ctx *ctx, void *req, inum_t ino,
                    const char *name)
{
    REQUEST(removexattr, ino, name);
}

void
request_access(struct request_ctx *ctx, void *req, inum_t ino, int mask)
{
    REQUEST(access, ino, mask);
}

void
request_create(struct request_ctx *ctx, void *req, inum_t parent,
               const char *name, mode_t mode, struct file_info *fi)
{
    REQUEST(create, parent, name, mode, fi);
}

void
request_fallocate(struct request_ctx *ctx, void *req, inum_t ino, int mode,
                  off_t offset, off_t length, struct file_info *fi)
{
    REQUEST(fallocate, ino, mode, offset, length, fi);
}

int
reply_err(void *req, int err)
{
    struct request *r = (struct request *)req;

    if (err < 0) {
        fprintf(stderr, "Error code in file system reply is negative: %d\n",
                err);
        write_backtrace(stderr, 1);
        abort();
    }

    return (*(r->ctx->reply_ops->reply_err))(r->req, err);
}

void
reply_none(void *req)
{
    struct request *r = (struct request *)req;

    (*(r->ctx->reply_ops->reply_none))(r->req);
}

int
reply_entry(void *req, const struct entry_param *e)
{
    struct request *r = (struct request *)req;

    return (*(r->ctx->reply_ops->reply_entry))(r->req, e);
}

int
reply_create(void *req, const struct entry_param *e, struct file_info *fi)
{
    struct request *r = (struct request *)req;

    return (*(r->ctx->reply_ops->reply_create))(r->req, e, fi);
}

int
reply_attr(void *req, const struct stat *attr, double attr_timeout)
{
    struct request *r = (struct request *)req;

    return (*(r->ctx->reply_ops->reply_attr))(r->req, attr, attr_timeout);
}

int
reply_readlink(void *req, const char *link)
{
    struct request *r = (struct request *)req;

    return (*(r->ctx->reply_ops->reply_readlink))(r->req, link);
}

int
reply_open(void *req, const struct file_info *fi)
{
    struct request *r = (struct request *)req;

    return (*(r->ctx->reply_ops->reply_open))(r->req, fi);
}

int
reply_write(void *req, size_t count)
{
    struct request *r = (struct request *)req;

    return (*(r->ctx->reply_ops->reply_write))(r->req, count);
}

int
reply_buf(void *req, const char *buf, size_t size)
{
    struct request *r = (struct request *)req;

    return (*(r->ctx->reply_ops->reply_buf))(r->req, buf, size);
}

int
reply_iov(void *req, const struct iovec *iov, int count)
{
    struct request *r = (struct request *)req;

    return (*(r->ctx->reply_ops->reply_iov))(r->req, iov, count);
}

int
reply_statfs(void *req, const struct statvfs *stbuf)
{
    struct request *r = (struct request *)req;

    return (*(r->ctx->reply_ops->reply_statfs))(r->req, stbuf);
}

int
reply_xattr(void *req, size_t count)
{
    struct request *r = (struct request *)req;

    return (*(r->ctx->reply_ops->reply_xattr))(r->req, count);
}

size_t
add_direntry(void *req, char *buf, size_t bufsize, const char *name,
             const struct stat *stbuf, off_t off)
{
    struct request *r = (struct request *)req;

    return (*(r->ctx->reply_ops->add_direntry))(r->req, buf, bufsize, name,
                                                stbuf, off);
}

const struct ctx *
req_ctx(void *req)
{
    struct request *r = (struct request *)req;

    return (*(r->ctx->reply_ops->req_ctx))(r->req);
}

void *
req_userdata(void *req)
{
    struct request *r = (struct request *)req;

    return r->ctx->rctx;
}

void
sess_exit(struct session *sess)
{
    (*(sess->sess_ops->exit))(sess->sctx);
}

static void
init_fuse_entry_param(struct fuse_entry_param *dst,
                      const struct entry_param *src)
{
    dst->ino = src->ino;
    dst->generation = src->generation;
    dst->attr = src->attr;
    dst->attr_timeout = src->attr_timeout;
    dst->entry_timeout = src->entry_timeout;
}

static void
init_ctx(struct ctx *dst, const struct fuse_ctx *src)
{
    dst->uid = src->uid;
    dst->gid = src->gid;
    dst->pid = src->pid;
    dst->umask = src->umask;
}

static void
init_file_info(struct file_info *dst, const struct fuse_file_info *src)
{
    dst->flags = src->flags;
    dst->fh = src->fh;
}

static void
set_fuse_file_info(struct fuse_file_info *dst, const struct file_info *src)
{
    dst->fh = src->fh;
}

int
request_fuse_init_prepare(struct request_ctx *ctx)
{
    return request_init_prepare(ctx, FUSE_ROOT_ID);
}

static void
request_fuse_init(void *userdata, struct fuse_conn_info *conn)
{
    struct request_ctx *ctx = (struct request_ctx *)userdata;

#if FUSE_USE_VERSION == 32
    conn->want = FUSE_CAP_ASYNC_READ | FUSE_CAP_EXPORT_SUPPORT
                 | FUSE_CAP_WRITEBACK_CACHE;
#else
    conn->want = FUSE_CAP_ASYNC_READ | FUSE_CAP_BIG_WRITES
                 | FUSE_CAP_EXPORT_SUPPORT;
#endif

    request_init(ctx, FUSE_ROOT_ID);
}

static void
request_fuse_destroy(void *userdata)
{
    struct request_ctx *ctx = (struct request_ctx *)userdata;

    request_destroy(ctx);
}

int
request_fuse_destroy_finish(struct request_ctx *ctx)
{
    return request_destroy_finish(ctx);
}

static void
request_fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_lookup(ctx, &r, parent, name);
}

static void
#if FUSE_USE_VERSION == 32
request_fuse_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
#else
request_fuse_forget(fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
#endif
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_forget(ctx, &r, ino, nlookup);
}

static void
request_fuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct file_info filei, *fileip;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    if (fi == NULL)
        fileip = NULL;
    else {
        init_file_info(&filei, fi);
        fileip = &filei;
    }

    request_getattr(ctx, &r, ino, fileip);
}

#define FLAG_MAP_ENTRY(fl) \
    {.fuse_flag = FUSE_SET_ATTR_##fl, .flag = REQUEST_SET_ATTR_##fl}

static void
request_fuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                     int to_set, struct fuse_file_info *fi)
{
    int set;
    size_t i;
    struct file_info filei, *fileip;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    static const struct ent {
        int fuse_flag;
        int flag;
    } fl_map[] = {
        FLAG_MAP_ENTRY(MODE),
        FLAG_MAP_ENTRY(UID),
        FLAG_MAP_ENTRY(GID),
        FLAG_MAP_ENTRY(SIZE),
        FLAG_MAP_ENTRY(ATIME),
        FLAG_MAP_ENTRY(MTIME),
        FLAG_MAP_ENTRY(ATIME_NOW),
        FLAG_MAP_ENTRY(MTIME_NOW)
    };

    set = 0;
    for (i = 0; i < ARRAY_SIZE(fl_map); i++) {
        const struct ent *fl = &fl_map[i];

        if (to_set & fl->fuse_flag)
            set |= fl->flag;
    }

    if (fi == NULL)
        fileip = NULL;
    else {
        init_file_info(&filei, fi);
        fileip = &filei;
    }

    request_setattr(ctx, &r, ino, attr, set, fileip);
}

#undef FLAG_MAP_ENTRY

static void
request_fuse_readlink(fuse_req_t req, fuse_ino_t ino)
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_readlink(ctx, &r, ino);
}

static void
request_fuse_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
                   mode_t mode, dev_t rdev)
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_mknod(ctx, &r, parent, name, mode, rdev);
}

static void
request_fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
                   mode_t mode)
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_mkdir(ctx, &r, parent, name, mode);
}

static void
request_fuse_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_unlink(ctx, &r, parent, name);
}

static void
request_fuse_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_rmdir(ctx, &r, parent, name);
}

static void
request_fuse_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
                     const char *name)
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_symlink(ctx, &r, link, parent, name);
}

static void
#if FUSE_USE_VERSION == 32
request_fuse_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
                    fuse_ino_t newparent, const char *newname,
                    unsigned int flags)
#else
request_fuse_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
                    fuse_ino_t newparent, const char *newname)
#endif
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

#if FUSE_USE_VERSION == 32
    (void)flags;
#endif

    request_rename(ctx, &r, parent, name, newparent, newname);
}

static void
request_fuse_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
                  const char *newname)
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_link(ctx, &r, ino, newparent, newname);
}

static void
request_fuse_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct file_info filei;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    init_file_info(&filei, fi);

    request_open(ctx, &r, ino, &filei);
}

static void
request_fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                  struct fuse_file_info *fi)
{
    struct file_info filei;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    init_file_info(&filei, fi);

    request_read(ctx, &r, ino, size, off, &filei);
}

static void
request_fuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size,
                   off_t off, struct fuse_file_info *fi)
{
    struct file_info filei;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    init_file_info(&filei, fi);

    request_write(ctx, &r, ino, buf, size, off, &filei);
}

static void
request_fuse_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct file_info filei;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    init_file_info(&filei, fi);

    request_flush(ctx, &r, ino, &filei);
}

static void
request_fuse_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct file_info filei;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    init_file_info(&filei, fi);

    request_opendir(ctx, &r, ino, &filei);
}

static void
request_fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                     struct fuse_file_info *fi)
{
    struct file_info filei;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    init_file_info(&filei, fi);

    request_readdir(ctx, &r, ino, size, off, &filei);
}

static void
request_fuse_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct file_info filei;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    init_file_info(&filei, fi);

    request_release(ctx, &r, ino, &filei);
}

static void
request_fuse_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
                   struct fuse_file_info *fi)
{
    struct file_info filei;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    init_file_info(&filei, fi);

    request_fsync(ctx, &r, ino, datasync, &filei);
}

static void
request_fuse_releasedir(fuse_req_t req, fuse_ino_t ino,
                        struct fuse_file_info *fi)
{
    struct file_info filei;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    init_file_info(&filei, fi);

    request_releasedir(ctx, &r, ino, &filei);
}

static void
request_fuse_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
                      struct fuse_file_info *fi)
{
    struct file_info filei;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    init_file_info(&filei, fi);

    request_fsyncdir(ctx, &r, ino, datasync, &filei);
}

static void
request_fuse_statfs(fuse_req_t req, fuse_ino_t ino)
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_statfs(ctx, &r, ino);
}

static void
#ifdef __APPLE__
request_fuse_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                      const char *value, size_t size, int flags,
                      uint32_t position)
#else
request_fuse_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                      const char *value, size_t size, int flags)
#endif
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

#ifdef __APPLE__
    if (position > 0) {
        fuse_reply_err(req, ENOTSUP);
        return;
    }

#endif
    request_setxattr(ctx, &r, ino, name, value, size, flags);
}

static void
#ifdef __APPLE__
request_fuse_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                      size_t size, uint32_t position)
#else
request_fuse_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                      size_t size)
#endif
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

#ifdef __APPLE__
    if (position > 0) {
        fuse_reply_err(req, ENOTSUP);
        return;
    }

#endif
    request_getxattr(ctx, &r, ino, name, size);
}

static void
request_fuse_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_listxattr(ctx, &r, ino, size);
}

static void
request_fuse_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name)
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_removexattr(ctx, &r, ino, name);
}

static void
request_fuse_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE_NO_FI(r);

    request_access(ctx, &r, ino, mask);
}

static void
request_fuse_create(fuse_req_t req, fuse_ino_t parent, const char *name,
                    mode_t mode, struct fuse_file_info *fi)
{
    struct file_info filei;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    init_file_info(&filei, fi);

    request_create(ctx, &r, parent, name, mode, &filei);
}

static void
request_fuse_fallocate(fuse_req_t req, fuse_ino_t ino, int mode, off_t offset,
                       off_t length, struct fuse_file_info *fi)
{
    struct file_info filei;
    struct request_ctx *ctx = fuse_req_userdata(req);
    REQUEST_FUSE(r);

    init_file_info(&filei, fi);

    request_fallocate(ctx, &r, ino, mode, offset, length, &filei);
}

static int
reply_fuse_err(void *req, int err)
{
    struct request_fuse *r = (struct request_fuse *)req;

    return fuse_reply_err(r->req, err);
}

static void
reply_fuse_none(void *req)
{
    struct request_fuse *r = (struct request_fuse *)req;

    fuse_reply_none(r->req);
}

static int
reply_fuse_entry(void *req, const struct entry_param *e)
{
    struct fuse_entry_param ent;
    struct request_fuse *r = (struct request_fuse *)req;

    init_fuse_entry_param(&ent, e);

    return fuse_reply_entry(r->req, &ent);
}

static int
reply_fuse_create(void *req, const struct entry_param *e,
                  const struct file_info *fi)
{
    struct fuse_entry_param ent;
    struct request_fuse *r = (struct request_fuse *)req;

    init_fuse_entry_param(&ent, e);
    set_fuse_file_info(r->fi, fi);

    return fuse_reply_create(r->req, &ent, r->fi);
}

static int
reply_fuse_attr(void *req, const struct stat *attr, double attr_timeout)
{
    struct request_fuse *r = (struct request_fuse *)req;

    return fuse_reply_attr(r->req, attr, attr_timeout);
}

static int
reply_fuse_readlink(void *req, const char *link)
{
    struct request_fuse *r = (struct request_fuse *)req;

    return fuse_reply_readlink(r->req, link);
}

static int
reply_fuse_open(void *req, const struct file_info *fi)
{
    struct request_fuse *r = (struct request_fuse *)req;

    set_fuse_file_info(r->fi, fi);

    return fuse_reply_open(r->req, r->fi);
}

static int
reply_fuse_write(void *req, size_t count)
{
    struct request_fuse *r = (struct request_fuse *)req;

    return fuse_reply_write(r->req, count);
}

static int
reply_fuse_buf(void *req, const char *buf, size_t size)
{
    struct request_fuse *r = (struct request_fuse *)req;

    return fuse_reply_buf(r->req, buf, size);
}

static int
reply_fuse_iov(void *req, const struct iovec *iov, int count)
{
    struct request_fuse *r = (struct request_fuse *)req;

    return fuse_reply_iov(r->req, iov, count);
}

static int
reply_fuse_statfs(void *req, const struct statvfs *stbuf)
{
    struct request_fuse *r = (struct request_fuse *)req;

    return fuse_reply_statfs(r->req, stbuf);
}

static int
reply_fuse_xattr(void *req, size_t count)
{
    struct request_fuse *r = (struct request_fuse *)req;

    return fuse_reply_xattr(r->req, count);
}

static size_t
add_direntry_fuse(void *req, char *buf, size_t bufsize, const char *name,
                  const struct stat *stbuf, off_t off)
{
    struct request_fuse *r = (struct request_fuse *)req;

    return fuse_add_direntry(r->req, buf, bufsize, name, stbuf, off);
}

static const struct ctx *
req_ctx_fuse(void *req)
{
    const struct fuse_ctx *ctx;
    struct request_fuse *r = (struct request_fuse *)req;

    ctx = fuse_req_ctx(r->req);

    init_ctx(&r->ctx, ctx);

    return &r->ctx;
}

struct fuse_lowlevel_ops request_fuse_ops = {
    .init           = &request_fuse_init,
    .destroy        = &request_fuse_destroy,
    .lookup         = &request_fuse_lookup,
    .forget         = &request_fuse_forget,
    .getattr        = &request_fuse_getattr,
    .setattr        = &request_fuse_setattr,
    .readlink       = &request_fuse_readlink,
    .mknod          = &request_fuse_mknod,
    .mkdir          = &request_fuse_mkdir,
    .unlink         = &request_fuse_unlink,
    .rmdir          = &request_fuse_rmdir,
    .symlink        = &request_fuse_symlink,
    .rename         = &request_fuse_rename,
    .link           = &request_fuse_link,
    .open           = &request_fuse_open,
    .read           = &request_fuse_read,
    .write          = &request_fuse_write,
    .flush          = &request_fuse_flush,
    .release        = &request_fuse_release,
    .fsync          = &request_fuse_fsync,
    .opendir        = &request_fuse_opendir,
    .readdir        = &request_fuse_readdir,
    .releasedir     = &request_fuse_releasedir,
    .fsyncdir       = &request_fuse_fsyncdir,
    .statfs         = &request_fuse_statfs,
    .setxattr       = &request_fuse_setxattr,
    .getxattr       = &request_fuse_getxattr,
    .listxattr      = &request_fuse_listxattr,
    .removexattr    = &request_fuse_removexattr,
    .access         = &request_fuse_access,
    .create         = &request_fuse_create,
    .fallocate      = &request_fuse_fallocate
};

const struct reply_ops reply_default_ops = {
    .reply_err      = &reply_fuse_err,
    .reply_none     = &reply_fuse_none,
    .reply_entry    = &reply_fuse_entry,
    .reply_create   = &reply_fuse_create,
    .reply_attr     = &reply_fuse_attr,
    .reply_readlink = &reply_fuse_readlink,
    .reply_open     = &reply_fuse_open,
    .reply_write    = &reply_fuse_write,
    .reply_buf      = &reply_fuse_buf,
    .reply_iov      = &reply_fuse_iov,
    .reply_statfs   = &reply_fuse_statfs,
    .reply_xattr    = &reply_fuse_xattr,
    .add_direntry   = &add_direntry_fuse,
    .req_ctx        = &req_ctx_fuse
};

/* vi: set expandtab sw=4 ts=4: */
