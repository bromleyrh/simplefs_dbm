/*
 * request.h
 */

#ifndef _REQUEST_H
#define _REQUEST_H

#include "ops.h"

#include <stdint.h>

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/uio.h>

struct request_ctx;

struct session;

typedef unsigned long inum_t;

struct entry_param {
    ino_t           ino;
    unsigned long   generation;
    struct stat     attr;
    double          attr_timeout;
    double          entry_timeout;
};

struct ctx {
    uid_t   uid;
    gid_t   gid;
    pid_t   pid;
    mode_t  umask;
};

struct file_info {
    int         flags;
    unsigned    keep_cache;
    uint64_t    fh;
};

struct request_ops {
    int (*new)(void *rctx);
    void (*end)(void *rctx);

    int (*init_prepare)(void *rctx, struct session *sess, inum_t root_id);
    void (*init)(void *rctx, struct session *sess, inum_t root_id);
    void (*destroy)(void *rctx);
    int (*destroy_finish)(void *rctx);
    void (*lookup)(void *req, inum_t parent, const char *name);
    void (*forget)(void *req, inum_t ino, uint64_t nlookup);
    void (*getattr)(void *req, inum_t ino, struct file_info *fi);
    void (*setattr)(void *req, inum_t ino, struct stat *attr, int to_set,
                    struct file_info *fi);
    void (*readlink)(void *req, inum_t ino);
    void (*mknod)(void *req, inum_t parent, const char *name, mode_t mode,
                  dev_t rdev);
    void (*mkdir)(void *req, inum_t parent, const char *name, mode_t mode);
    void (*unlink)(void *req, inum_t parent, const char *name);
    void (*rmdir)(void *req, inum_t parent, const char *name);
    void (*symlink)(void *req, const char *link, inum_t parent,
                    const char *name);
    void (*rename)(void *req, inum_t parent, const char *name, inum_t newparent,
                   const char *newname);
    void (*link)(void *req, inum_t ino, inum_t newparent, const char *newname);
    void (*open)(void *req, inum_t ino, struct file_info *fi);
    void (*read)(void *req, inum_t ino, size_t size, off_t off,
                 struct file_info *fi);
    void (*write)(void *req, inum_t ino, const char *buf, size_t size,
                  off_t off, struct file_info *fi);
    void (*flush)(void *req, inum_t ino, struct file_info *fi);
    void (*opendir)(void *req, inum_t ino, struct file_info *fi);
    void (*readdir)(void *req, inum_t ino, size_t size, off_t off,
                    struct file_info *fi);
    void (*release)(void *req, inum_t ino, struct file_info *fi);
    void (*fsync)(void *req, inum_t ino, int datasync, struct file_info *fi);
    void (*releasedir)(void *req, inum_t ino, struct file_info *fi);
    void (*fsyncdir)(void *req, inum_t ino, int datasync, struct file_info *fi);
    void (*statfs)(void *req, inum_t ino);
    void (*setxattr)(void *req, inum_t ino, const char *name, const char *value,
                     size_t size, int flags);
    void (*getxattr)(void *req, inum_t ino, const char *name, size_t size);
    void (*listxattr)(void *req, inum_t ino, size_t size);
    void (*removexattr)(void *req, inum_t ino, const char *name);
    void (*access)(void *req, inum_t ino, int mask);
    void (*create)(void *req, inum_t parent, const char *name, mode_t mode,
                   struct file_info *fi);
    void (*fallocate)(void *req, inum_t ino, int mode, off_t offset,
                      off_t length, struct file_info *fi);
};

struct reply_ops {
    int (*reply_err)(void *req, int err);
    void (*reply_none)(void *req);
    int (*reply_entry)(void *req, const struct entry_param *e);
    int (*reply_create)(void *req, const struct entry_param *e,
                        const struct file_info *fi);
    int (*reply_attr)(void *req, const struct stat *attr, double attr_timeout);
    int (*reply_readlink)(void *req, const char *link);
    int (*reply_open)(void *req, const struct file_info *fi);
    int (*reply_write)(void *req, size_t count);
    int (*reply_buf)(void *req, const char *buf, size_t size);
    int (*reply_iov)(void *req, const struct iovec *iov, int count);
    int (*reply_statfs)(void *req, const struct statvfs *stbuf);
    int (*reply_xattr)(void *req, size_t count);

    size_t (*add_direntry)(void *req, char *buf, size_t bufsize,
                           const char *name, const struct stat *stbuf,
                           off_t off);

    const struct ctx *(*req_ctx)(void *req);
};

struct sess_ops {
    void (*exit)(void *sctx);
};

#define REQUEST_SET_ATTR_MODE 1
#define REQUEST_SET_ATTR_UID 2
#define REQUEST_SET_ATTR_GID 4
#define REQUEST_SET_ATTR_SIZE 8
#define REQUEST_SET_ATTR_ATIME 16
#define REQUEST_SET_ATTR_MTIME 32
#define REQUEST_SET_ATTR_ATIME_NOW 64
#define REQUEST_SET_ATTR_MTIME_NOW 128

#define REQUEST_DEFAULT REQUEST_SIMPLEFS

extern const struct reply_ops reply_default_ops;
#define REPLY_DEFAULT (&reply_default_ops)

int request_new(struct request_ctx **ctx, const struct request_ops *req_ops,
                const struct reply_ops *reply_ops, void *rctx,
                const struct sess_ops *sess_ops, void *sctx);
void request_end(struct request_ctx *ctx);

int request_init_prepare(struct request_ctx *ctx, inum_t root_id);
void request_init(struct request_ctx *ctx, inum_t root_id);
void request_destroy(struct request_ctx *ctx);
int request_destroy_finish(struct request_ctx *ctx);
void request_lookup(struct request_ctx *ctx, void *req, inum_t parent,
                    const char *name);
void request_forget(struct request_ctx *ctx, void *req, inum_t ino,
                    uint64_t nlookup);
void request_getattr(struct request_ctx *ctx, void *req, inum_t ino,
                     struct file_info *fi);
void request_setattr(struct request_ctx *ctx, void *req, inum_t ino,
                     struct stat *attr, int to_set, struct file_info *fi);
void request_readlink(struct request_ctx *ctx, void *req, inum_t ino);
void request_mknod(struct request_ctx *ctx, void *req, inum_t parent,
                   const char *name, mode_t mode, dev_t rdev);
void request_mkdir(struct request_ctx *ctx, void *req, inum_t parent,
                   const char *name, mode_t mode);
void request_unlink(struct request_ctx *ctx, void *req, inum_t parent,
                    const char *name);
void request_rmdir(struct request_ctx *ctx, void *req, inum_t parent,
                   const char *name);
void request_symlink(struct request_ctx *ctx, void *req, const char *link,
                     inum_t parent, const char *name);
void request_rename(struct request_ctx *ctx, void *req, inum_t parent,
                    const char *name, inum_t newparent, const char *newname);
void request_link(struct request_ctx *ctx, void *req, inum_t ino,
                  inum_t newparent, const char *newname);
void request_open(struct request_ctx *ctx, void *req, inum_t ino,
                  struct file_info *fi);
void request_read(struct request_ctx *ctx, void *req, inum_t ino, size_t size,
                  off_t off, struct file_info *fi);
void request_write(struct request_ctx *ctx, void *req, inum_t ino,
                   const char *buf, size_t size, off_t off,
                   struct file_info *fi);
void request_flush(struct request_ctx *ctx, void *req, inum_t ino,
                   struct file_info *fi);
void request_opendir(struct request_ctx *ctx, void *req, inum_t ino,
                     struct file_info *fi);
void request_readdir(struct request_ctx *ctx, void *req, inum_t ino,
                     size_t size, off_t off, struct file_info *fi);
void request_release(struct request_ctx *ctx, void *req, inum_t ino,
                     struct file_info *fi);
void request_fsync(struct request_ctx *ctx, void *req, inum_t ino, int datasync,
                   struct file_info *fi);
void request_releasedir(struct request_ctx *ctx, void *req, inum_t ino,
                        struct file_info *fi);
void request_fsyncdir(struct request_ctx *ctx, void *req, inum_t ino,
                      int datasync, struct file_info *fi);
void request_statfs(struct request_ctx *ctx, void *req, inum_t ino);
void request_setxattr(struct request_ctx *ctx, void *req, inum_t ino,
                      const char *name, const char *value, size_t size,
                      int flags);
void request_getxattr(struct request_ctx *ctx, void *req, inum_t ino,
                      const char *name, size_t size);
void request_listxattr(struct request_ctx *ctx, void *req, inum_t ino,
                       size_t size);
void request_removexattr(struct request_ctx *ctx, void *req, inum_t ino,
                         const char *name);
void request_access(struct request_ctx *ctx, void *req, inum_t ino, int mask);
void request_create(struct request_ctx *ctx, void *req, inum_t parent,
                    const char *name, mode_t mode, struct file_info *fi);
void request_fallocate(struct request_ctx *ctx, void *req, inum_t ino, int mode,
                       off_t offset, off_t length, struct file_info *fi);

int reply_err(void *req, int err);
void reply_none(void *req);
int reply_entry(void *req, const struct entry_param *e);
int reply_create(void *req, const struct entry_param *e, struct file_info *fi);
int reply_attr(void *req, const struct stat *attr, double attr_timeout);
int reply_readlink(void *req, const char *link);
int reply_open(void *req, const struct file_info *fi);
int reply_write(void *req, size_t count);
int reply_buf(void *req, const char *buf, size_t size);
int reply_iov(void *req, const struct iovec *iov, int count);
int reply_statfs(void *req, const struct statvfs *stbuf);
int reply_xattr(void *req, size_t count);

size_t add_direntry(void *req, char *buf, size_t bufsize, const char *name,
                    const struct stat *stbuf, off_t off);

void *req_userdata(void *req);
const struct ctx *req_ctx(void *req);

void sess_exit(struct session *sess);

#endif

/* vi: set expandtab sw=4 ts=4: */
