/*
 * fuse_conn.h
 */

#ifndef _FUSE_CONN_H
#define _FUSE_CONN_H

#include <stddef.h>
#include <stdint.h>

#include <sys/stat.h>
#include <sys/types.h>

struct fuse_conn;

struct fuse_conn_params {
    unsigned want;
};

struct fuse_conn_req;
typedef struct fuse_conn_req *fuse_conn_req_t;

typedef unsigned long fuse_conn_ino_t;

struct fuse_conn_file_info {
    int         flags;
    uint64_t    fh;
    unsigned    keep_cache:1;
    unsigned    flush:1;
    unsigned    writepage:1;
};

struct fuse_conn_ops {
    void (*init)(void *userdata, struct fuse_conn_params *conn);
    void (*destroy)(void *userdata);
    void (*lookup)(fuse_conn_req_t req, fuse_conn_ino_t parent,
                   const char *name);
    void (*forget)(fuse_conn_req_t req, fuse_conn_ino_t ino,
                   unsigned long nlookup);
    void (*getattr)(fuse_conn_req_t req, fuse_conn_ino_t ino,
                    struct fuse_conn_file_info *fi);
    void (*setattr)(fuse_conn_req_t req, fuse_conn_ino_t ino, struct stat *attr,
                    int to_set, struct fuse_conn_file_info *fi);
    void (*access)(fuse_conn_req_t req, fuse_conn_ino_t ino, int mask);
    void (*mknod)(fuse_conn_req_t req, fuse_conn_ino_t parent, const char *name,
                  mode_t mode, dev_t rdev);
    void (*mkdir)(fuse_conn_req_t req, fuse_conn_ino_t parent, const char *name,
                  mode_t mode);
    void (*link)(fuse_conn_req_t req, fuse_conn_ino_t ino,
                 fuse_conn_ino_t newparent, const char *newname);
    void (*rename)(fuse_conn_req_t req, fuse_conn_ino_t parent,
                   const char *name, fuse_conn_ino_t newparent,
                   const char *newname);
    void (*unlink)(fuse_conn_req_t req, fuse_conn_ino_t parent,
                   const char *name);
    void (*rmdir)(fuse_conn_req_t req, fuse_conn_ino_t parent,
                  const char *name);
    void (*symlink)(fuse_conn_req_t req, const char *link,
                    fuse_conn_ino_t parent, const char *name);
    void (*readlink)(fuse_conn_req_t req, fuse_conn_ino_t ino);
    void (*create)(fuse_conn_req_t req, fuse_conn_ino_t parent,
                   const char *name, mode_t mode,
                   struct fuse_conn_file_info *fi);
    void (*open)(fuse_conn_req_t req, fuse_conn_ino_t ino,
                 struct fuse_conn_file_info *fi);
    void (*flush)(fuse_conn_req_t req, struct fuse_conn_file_info *fi);
    void (*release)(fuse_conn_req_t req, fuse_conn_ino_t ino,
                    struct fuse_conn_file_info *fi);
    void (*read)(fuse_conn_req_t req, fuse_conn_ino_t ino, size_t size,
                 off_t off, struct fuse_conn_file_info *fi);
    void (*write)(fuse_conn_req_t req, fuse_conn_ino_t ino, const char *buf,
                  size_t size, off_t off, struct fuse_conn_file_info *fi);
    void (*fallocate)(fuse_conn_req_t req, fuse_conn_ino_t ino, int mode,
                      off_t offset, off_t length,
                      struct fuse_conn_file_info *fi);
    void (*fsync)(fuse_conn_req_t req, fuse_conn_ino_t ino, int datasync,
                  struct fuse_conn_file_info *fi);
    void (*opendir)(fuse_conn_req_t req, fuse_conn_ino_t ino,
                    struct fuse_conn_file_info *fi);
    void (*releasedir)(fuse_conn_req_t req, fuse_conn_ino_t ino,
                       struct fuse_conn_file_info *fi);
    void (*readdir)(fuse_conn_req_t req, fuse_conn_ino_t ino, size_t size,
                    off_t off, struct fuse_conn_file_info *fi);
    void (*fsyncdir)(fuse_conn_req_t req, fuse_conn_ino_t ino, int datasync,
                     struct fuse_conn_file_info *fi);
    void (*setxattr)(fuse_conn_req_t req, fuse_conn_ino_t ino, const char *name,
                     const char *value, size_t size, int flags);
    void (*getxattr)(fuse_conn_req_t req, fuse_conn_ino_t ino, const char *name,
                     size_t size);
    void (*listxattr)(fuse_conn_req_t req, fuse_conn_ino_t ino, size_t size);
    void (*removexattr)(fuse_conn_req_t req, fuse_conn_ino_t ino,
                        const char *name);
    void (*statfs)(fuse_conn_req_t req, fuse_conn_ino_t ino);
};

int fuse_conn_new(struct fuse_conn **conn, const struct fuse_conn_ops *ops);

int fuse_conn_destroy(struct fuse_conn *conn, int force);

int fuse_conn_mount(struct fuse_conn *conn, int dfd, const char *target);

int fuse_conn_loop(struct fuse_conn *conn);

#endif

/* vi: set expandtab sw=4 ts=4: */
