/*
 * fuse_conn.c
 */

#include "common.h"
#include "fuse_conn.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <search.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define FUSE_DEVICE _PATH_DEV "fuse"

#define MOUNT_BIN "mount"

#define FUSE_KERNEL_VERSION 7
#define FUSE_KERNEL_MINOR_VERSION 26

struct arg {
    struct arg  *next;
    struct arg  *prev;
    const char  *s;
};

struct argval {
    union {
        long        lval;
        const char  *sval;
    };
    enum {
        LONG = 1,
        STRING
    } type;
};

struct argspriv {
    struct arg *args_list;
};

struct std_opt_data {
    char    *mountpoint;
    int     foreground;
};

struct fuse_conn {
    const struct fuse_conn_ops  *ops;
    void                        *userdata;
    enum {
        DEV_OPEN = 1,
        DEV_MOUNTED,
        DEV_UNMOUNTED
    } state;
    int                         devfd;
};

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

struct fuse_entry_out {
    uint64_t            nodeid;
    uint64_t            generation;
    uint64_t            entry_valid;
    uint64_t            attr_valid;
    uint32_t            entry_valid_nsec;
    uint32_t            attr_valid_nsec;
    struct fuse_attr    attr;
};

struct fuse_attr_out {
    uint64_t            attr_valid;
    uint32_t            attr_valid_nsec;
    uint32_t            dummy;
    struct fuse_attr    attr;
};

struct fuse_dirent {
    uint64_t    ino;
    uint64_t    off;
    uint32_t    namelen;
    uint32_t    type;
    char        name[0];
};

/* FORGET */

struct fuse_forget_in {
    uint64_t nlookup;
};

/* GETATTR */

#define FUSE_GETATTR_FH 1

struct fuse_getattr_in {
    uint32_t getattr_flags;
    uint32_t dummy;
    uint64_t fh;
};

/* SETATTR */

#define FATTR_MODE         1
#define FATTR_UID          2
#define FATTR_GID          4
#define FATTR_SIZE         8
#define FATTR_ATIME       16
#define FATTR_MTIME       32
#define FATTR_FH          64
#define FATTR_ATIME_NOW  128
#define FATTR_MTIME_NOW  256
#define FATTR_LOCKOWNER  512
#define FATTR_CTIME     1024

struct fuse_setattr_in {
    uint32_t valid;
    uint32_t padding;
    uint64_t fh;
    uint64_t size;
    uint64_t lock_owner;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint32_t atimensec;
    uint32_t mtimensec;
    uint32_t ctimensec;
    uint32_t mode;
    uint32_t unused4;
    uint32_t uid;
    uint32_t gid;
    uint32_t unused5;
};

/* MKNOD */

struct fuse_mknod_in {
    uint32_t mode;
    uint32_t rdev;
    uint32_t umask;
    uint32_t padding;
};

/* MKDIR */

struct fuse_mkdir_in {
    uint32_t mode;
    uint32_t umask;
};

/* RENAME */

struct fuse_rename_in {
    uint64_t newdir;
};

/* LINK */

struct fuse_link_in {
    uint64_t oldnodeid;
};

/* OPEN */

struct fuse_open_in {
    uint32_t flags;
    uint32_t unused;
};

#define FOPEN_DIRECT_IO     1
#define FOPEN_KEEP_CACHE    2
#define FOPEN_NONSEEKABLE   4
#define FOPEN_CACHE_DIR     8

struct fuse_open_out {
    uint64_t fh;
    uint32_t open_flags;
    uint32_t padding;
};

/* READ */

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

/* WRITE */

#define FUSE_WRITE_CACHE        1
#define FUSE_WRITE_LOCKOWNER    2

struct fuse_write_in {
    uint64_t fh;
    uint64_t offset;
    uint32_t size;
    uint32_t write_flags;
    uint64_t lock_owner;
    uint32_t flags;
    uint32_t padding;
};

struct fuse_write_out {
    uint32_t size;
    uint32_t padding;
};

/* STATFS */

struct fuse_statfs_out {
    struct fuse_kstatfs st;
};

/* RELEASE */

#define FUSE_RELEASE_FLUSH          1
#define FUSE_RELEASE_FLOCK_UNLOCK   2

struct fuse_release_in {
    uint64_t fh;
    uint32_t flags;
    uint32_t release_flags;
    uint64_t lock_owner;
};

/* FSYNC */

struct fuse_fsync_in {
    uint64_t fh;
    uint32_t fsync_flags;
    uint32_t padding;
};

/* SETXATTR */

struct fuse_setxattr_in {
    uint32_t size;
    uint32_t flags;
};

/* GETXATTR */

struct fuse_getxattr_in {
    uint32_t size;
    uint32_t padding;
};

struct fuse_getxattr_out {
    uint32_t size;
    uint32_t padding;
};

/* FLUSH */

struct fuse_flush_in {
    uint64_t fh;
    uint32_t unused;
    uint32_t padding;
    uint64_t lock_owner;
};

/* INIT */

#define FUSE_ASYNC_READ               1
#define FUSE_POSIX_LOCKS              2
#define FUSE_FILE_OPS                 4
#define FUSE_ATOMIC_O_TRUNC           8
#define FUSE_EXPORT_SUPPORT          16
#define FUSE_BIG_WRITES              32
#define FUSE_DONT_MASK               64
#define FUSE_SPLICE_WRITE           128
#define FUSE_SPLICE_MOVE            256
#define FUSE_SPLICE_READ            512
#define FUSE_FLOCK_LOCKS           1024
#define FUSE_HAS_IOCTL_DIR         2048
#define FUSE_AUTO_INVAL_DATA       4096
#define FUSE_DO_READDIRPLUS        8192
#define FUSE_ASYNC_DIO            16384
#define FUSE_WRITEBACK_CACHE      32768
#define FUSE_NO_OPEN_SUPPORT      65536
#define FUSE_PARALLEL_DIROPS     131072
#define FUSE_HANDLE_KILLPRIV     262144
#define FUSE_POSIX_ACL           524288
#define FUSE_ABORT_ERROR        1048576
#define FUSE_MAX_PAGES          2097152
#define FUSE_CACHE_SYMLINKS     4194304

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

/* ACCESS */

struct fuse_access_in {
    uint32_t mask;
    uint32_t padding;
};

/* CREATE */

struct fuse_create_in {
    uint32_t flags;
    uint32_t mode;
    uint32_t umask;
    uint32_t padding;
};

/* INTERRUPT */

struct fuse_interrupt_in {
    uint64_t unique;
};

/* FALLOCATE */

struct fuse_fallocate_in {
    uint64_t fh;
    uint64_t offset;
    uint64_t length;
    uint32_t mode;
    uint32_t padding;
};

static int init_argspriv(struct argspriv **);

static int conv_argv_to_list(int, char **, struct arg **);

static int handle_fmt_space(const char **, const char **, struct arg **);
static int handle_fmt_conv(const char **, const char *, struct argval *);

static int args_match(struct arg *, const struct fuse_conn_opt *,
                      struct argval *);

static int identify_match(struct arg *, const struct fuse_conn_opt *, int *,
                          int *, struct argval *);

static int perform_match_action(struct arg *, int,
                                const struct fuse_conn_opt *);

static int mount_device(int, const char *);

static int process_fuse_requests(struct fuse_conn *);

static int
init_argspriv(struct argspriv **priv)
{
    struct argspriv *ret;

    ret = malloc(sizeof(*ret));
    if (ret == NULL)
        return MINUS_ERRNO;

    ret->args_list = NULL;

    *priv = ret;
    return 0;
}

static int
conv_argv_to_list(int argc, char **argv, struct arg **list)
{
    int err;
    int i;
    struct arg *arg, *firstarg, *tmp;

    if (argc == 0) {
        *list = NULL;
        return 0;
    }

    firstarg = malloc(sizeof(*firstarg));
    if (firstarg == NULL)
        return MINUS_ERRNO;

    firstarg->s = strdup(argv[0]);
    if (firstarg->s == NULL) {
        free(firstarg);
        return MINUS_ERRNO;
    }

    insque(firstarg, NULL);

    tmp = firstarg;

    for (i = 1; i < argc; i++) {
        arg = malloc(sizeof(*arg));
        if (arg == NULL) {
            err = MINUS_ERRNO;
            goto err;
        }
        arg->s = strdup(argv[i]);
        if (arg->s == NULL) {
            err = MINUS_ERRNO;
            free(arg);
            goto err;
        }
        insque(arg, tmp);
        tmp = arg;
    }

    *list = firstarg;
    return 0;

err:
    for (arg = firstarg; arg != NULL; arg = tmp) {
        tmp = arg->next;
        free((void *)(arg->s));
        free(arg);
    }
    return err;
}

static int
handle_fmt_space(const char **fmts, const char **args, struct arg **arg)
{
    if (**args == '\0') { /* next argument */
        *arg = (*arg)->next;
        if (*arg == NULL)
            return -EINVAL;
        *args = &(*arg)->s[0];
    }

    while (isspace(*(++(*fmts))))
        ;

    return 0;
}

static int
handle_fmt_conv(const char **fmts, const char *args, struct argval *val)
{
    char *endptr;
    long lval;

    ++(*fmts);

    switch (**fmts) {
    case 'd':
        errno = 0;
        lval = strtol(args, &endptr, 10);
        if (errno != 0)
            return MINUS_ERRNO;
        if (*endptr != '\0')
            return -EINVAL;
        val->lval = lval;
        val->type = LONG;
        ++(*fmts);
        break;
    case 's':
        val->sval = args;
        val->type = STRING;
        ++(*fmts);
    case '%':
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static int
args_match(struct arg *arg, const struct fuse_conn_opt *opt, struct argval *val)
{
    const char *args, *fmts;
    int err;

    fmts = &opt->fmt[0];
    args = &arg->s[0];

    for (;;) {
        if (isspace(*fmts)) {
            err = handle_fmt_space(&fmts, &args, &arg);
            if (err)
                return err;
        }
        if (*fmts == '%') {
            err = handle_fmt_conv(&fmts, args, val);
            if (err)
                return err;
            continue;
        }
        /* exact match */
        if (*args != *fmts)
            return 0;
        if (*fmts == '\0')
            break;
        ++fmts;
        ++args;
    }

    return 1;
}

static int
identify_match(struct arg *arg, const struct fuse_conn_opt *opts, int *nargs,
               int *opti, struct argval *val)
{
    int i;
    int res;

    val->type = 0;

    for (i = 0; opts[i].fmt != NULL; i++) {
        res = args_match(arg, &opts[i], val);
        if (res != 0) {
            if (res < 0)
                return res;
            break;
        }
    }

    *nargs = res;
    *opti = i;
    return 0;
}

static int
perform_match_action(struct arg *arg, int nargs,
                     const struct fuse_conn_opt *opt)
{
    (void)arg;
    (void)nargs;
    (void)opt;

    return 0;
}

static int
mount_device(int dfd, const char *target)
{
    int err;
    int status;
    pid_t pid;

    pid = fork();
    if (pid == -1)
        return MINUS_ERRNO;
    if (pid == 0) {
        if ((dfd != AT_FDCWD) && (fchdir(dfd) == -1))
            perror("Error changing directory");
        else {
            execlp(MOUNT_BIN, MOUNT_BIN, "-t", "fuse", "fuse", target, NULL);
            perror("Error executing " MOUNT_BIN);
        }
        _exit(EXIT_FAILURE);
    }

    if (waitpid(pid, &status, 0) == -1) {
        err = MINUS_ERRNO;
        perror("Error executing " MOUNT_BIN);
        return err;
    }
    if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
        fputs("Error mounting FUSE file system\n", stderr);
        return -EIO;
    }

    return 0;
}

static int
process_fuse_requests(struct fuse_conn *conn)
{
    (void)conn;

    return -ENOSYS;
}

int
fuse_conn_args_parse_opts(struct fuse_conn_args *args, void *data,
                          const struct fuse_conn_opt *opts,
                          int (*opt_proc)(void *, const char *, int,
                                          struct fuse_conn_args *))
{
    int err;
    struct arg *arg;
    struct argspriv *priv;

    (void)data;
    (void)opt_proc;

    priv = (struct argspriv *)(args->priv);

    if (priv == NULL) {
        err = init_argspriv((struct argspriv **)&args->priv);
        if (err)
            return err;
        err = conv_argv_to_list(args->argc, args->argv, &priv->args_list);
        if (err)
            return err;
    }

    for (arg = priv->args_list; arg != NULL; arg = arg->next) {
        int nargs, opti;
        struct argval val;

        err = identify_match(arg, opts, &nargs, &opti, &val);
        if (err)
            return err;
        if (nargs > 0) {
            err = perform_match_action(arg, nargs, &opts[opti]);
            if (err)
                return err;
        }
    }

    return 0;
}

int
fuse_conn_args_parse_opts_std(struct fuse_conn_args *args, char **mountpoint,
                              int *multithreaded, int *foreground)
{
    int err;
    struct arg *arg;
    struct argspriv *priv;
    struct std_opt_data data;

    static const struct fuse_conn_opt opts[] = {
        {"%s", offsetof(struct std_opt_data, mountpoint), 0},
        {"-f", offsetof(struct std_opt_data, foreground), 1}
    };

    priv = (struct argspriv *)(args->priv);

    if (priv == NULL) {
        err = init_argspriv((struct argspriv **)&args->priv);
        if (err)
            return err;
        err = conv_argv_to_list(args->argc, args->argv, &priv->args_list);
        if (err)
            return err;
    }

    for (arg = priv->args_list; arg != NULL; arg = arg->next) {
        int nargs, opti;
        struct argval val;

        err = identify_match(arg, opts, &nargs, &opti, &val);
        if (err)
            return err;
        if (nargs > 0) {
            err = perform_match_action(arg, nargs, &opts[opti]);
            if (err)
                return err;
        }
    }

    *mountpoint = data.mountpoint;
    *multithreaded = 0;
    *foreground = data.foreground;
    return 0;
}

int
fuse_conn_args_add_mount_opt(struct fuse_conn_args *args, const char *mntopt)
{
    int err;
    struct arg *new_arg;
    struct argspriv *priv;

    new_arg = malloc(sizeof(*new_arg));
    if (new_arg == NULL)
        return MINUS_ERRNO;

    new_arg->s = strdup(mntopt);
    if (new_arg->s == NULL) {
        err = MINUS_ERRNO;
        goto err1;
    }

    priv = (struct argspriv *)(args->priv);

    if (priv == NULL) {
        err = init_argspriv((struct argspriv **)&args->priv);
        if (err)
            goto err2;
        err = conv_argv_to_list(args->argc, args->argv, &priv->args_list);
        if (err)
            return err;
    }

    insque(new_arg, priv->args_list);
    if (priv->args_list == NULL)
        priv->args_list = new_arg;

    return 0;

err2:
    free((void *)(new_arg->s));
err1:
    free(new_arg);
    return err;
}

void
fuse_conn_args_free(struct fuse_conn_args *args)
{
    struct arg *arg;
    struct argspriv *priv;

    priv = (struct argspriv *)(args->priv);

    if (priv == NULL)
        return;

    for (arg = priv->args_list; arg != NULL; arg = arg->next) {
        free((void *)(arg->s));
        free(arg);
    }

    free(priv);

    args->priv = NULL;
}

int
fuse_background(int flags)
{
    (void)flags;

    return -ENOSYS;
}

int
fuse_conn_new(struct fuse_conn **conn, const struct fuse_conn_args *args,
              const struct fuse_conn_ops *ops, void *userdata)
{
    int err;
    struct fuse_conn *ret;

    (void)args;

    ret = malloc(sizeof(*ret));
    if (ret == NULL)
        return MINUS_ERRNO;

    ret->devfd = open(FUSE_DEVICE, O_RDWR);
    if (ret->devfd == -1) {
        err = MINUS_ERRNO;
        free(ret);
        return err;
    }
    ret->state = DEV_OPEN;

    ret->ops = ops;
    ret->userdata = userdata;

    *conn = ret;
    return 0;
}

int
fuse_conn_destroy(struct fuse_conn *conn, int force)
{
    int ret;

    if (!force && (conn->state != DEV_UNMOUNTED))
        return -EINVAL;

    ret = (close(conn->devfd) == -1) ? MINUS_ERRNO : 0;

    free(conn);

    return ret;
}

int
fuse_conn_mount(struct fuse_conn *conn, int dfd, const char *target)
{
    int ret;

    if (conn->state != DEV_OPEN)
        return -EINVAL;

    ret = mount_device(dfd, target);
    if (ret == 0)
        conn->state = DEV_MOUNTED;

    return ret;
}

int
fuse_conn_loop(struct fuse_conn *conn)
{
    int ret;

    if (conn->state != DEV_MOUNTED)
        return -EINVAL;

    ret = process_fuse_requests(conn);
    if (ret == 1) {
        conn->state = DEV_UNMOUNTED;
        ret = 0;
    }

    return ret;
}

int
fuse_exec_unmount(int dfd, const char *target)
{
    (void)dfd;
    (void)target;

    return -ENOSYS;
}

/* vi: set expandtab sw=4 ts=4: */
