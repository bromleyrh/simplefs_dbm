/*
 * simplefs.c
 */

#include "config.h"

#include "common.h"
#include "ops.h"
#include "request.h"
#include "simplefs.h"
#include "util.h"

#include <forensics.h>
#include <strings_ext.h>

#include <files/acc_ctl.h>
#include <files/util.h>

#include <myutil/version.h>

#include <fuse.h>
#include <fuse_lowlevel.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

struct fuse_data {
    char                *mountpoint;
    int                 foreground;
    struct mount_data   md;
    struct fuse_chan    *chan;
    struct fuse_session *sess;
    struct request_ctx  *ctx;
    int                 aborted; /* session loop aborted by fuse_session_exit()
                                    call in simplefs, rather than external
                                    umount() on mount point */
};

struct errpipe_msg {
    int     err;
    size_t  msglen;
    char    buf[256];
};

#define ERRPIPE_MIN_MSGLEN offsetof(struct errpipe_msg, buf)

extern int fuse_cache_debug;

extern struct fuse_lowlevel_ops request_fuse_ops;

#define FSNAME PACKAGE_STRING
#define LIBNAME "libutil " LIBUTIL_VERSION

#define SIMPLEFS_CORE_DIR _PATH_VARTMP "simplefs/cores"

#define FUSERMOUNT_PATH "fusermount"

#define DEFAULT_FUSE_OPTIONS "default_permissions"

int request_fuse_init_prepare(struct request_ctx *);
int request_fuse_destroy_finish(struct request_ctx *);

static int set_cloexec(int);

static void int_handler(int);
static void abrt_handler(int, siginfo_t *, void *);

static int set_up_signal_handlers(void);

static int enable_debugging_features(void);

static void destroy_mount_data(struct mount_data *);

static int read_errpipe(int, const char **);
static int write_errpipe(int, int, const char *);

static int opt_proc(void *, const char *, int, struct fuse_args *);
static int do_fuse_parse_cmdline(struct fuse_args *, char **, int *, int *);
static int parse_cmdline(struct fuse_args *, struct fuse_data *);

static int set_privs(char *);

static struct fuse_session *do_fuse_mount(const char *, struct fuse_args *,
                                          const struct fuse_lowlevel_ops *,
                                          size_t, void *, struct fuse_chan **);
static int do_fuse_daemonize(pid_t *);
static int do_fuse_session_loop_mt(struct fuse_session *);
static void do_fuse_unmount(const char *, struct fuse_chan *,
                            struct fuse_session *);

static int do_unmount_path(const char *);

static int open_log(const char *);

static int init_fuse(struct fuse_args *, struct fuse_data *);
static int process_fuse_events(struct fuse_data *);
static int terminate_fuse(struct fuse_data *);

static int unmount_fuse(struct fuse_data *);

static void
simplefs_exit(void *sctx)
{
    struct fuse_data *fusedata = sctx;

    fuse_session_exit(fusedata->sess);
    fusedata->aborted = 1;
}

static const struct sess_ops sess_default_ops = {
    .exit = &simplefs_exit
};

static int
set_cloexec(int fd)
{
    int fl;

    fl = fcntl(fd, F_GETFL);
    if (fl == -1)
        return MINUS_ERRNO;

    if (!(fl & O_CLOEXEC)) {
        fl |= O_CLOEXEC;
        if (fcntl(fd, F_SETFL, fl) == -1)
            return MINUS_ERRNO;
    }

    return 0;
}

static void
int_handler(int signum)
{
    (void)signum;
}

static void
abrt_handler(int signum, siginfo_t *info, void *ucontext)
{
    int dfd;

    dfd = dir_create(SIMPLEFS_CORE_DIR, DIR_CREATE_PARENTS,
                     S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO);
    if (dfd >= 0) {
        fchdir(dfd);
        close(dfd);
    }

    if (signum == SIGSEGV)
        sigaction_segv_diag(signum, info, ucontext);

    signal(signum, SIG_DFL);
    raise(signum);
}

static int
set_up_signal_handlers()
{
    static const struct sigaction sa_term = {
        .sa_handler = &int_handler
    }, sa_pipe = {
        .sa_handler = SIG_IGN
    };

    return sigaction(SIGINT, &sa_term, NULL) == -1
           || sigaction(SIGTERM, &sa_term, NULL) == -1
           || sigaction(SIGHUP, &sa_pipe, NULL) == -1
           || sigaction(SIGPIPE, &sa_pipe, NULL) == -1
           ? MINUS_ERRNO : 0;
}

static int
enable_debugging_features()
{
    const char *errmsg;
    int err;
    struct sigaction sa;

    static const struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY
    };

    omemset(&sa, 0);
    sa.sa_sigaction = &abrt_handler;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGABRT, &sa, NULL) == -1
        || sigaction(SIGSEGV, &sa, NULL) == -1) {
        errmsg = "Error setting signal handler";
        goto err;
    }

    if (setrlimit(RLIMIT_CORE, &rlim) == -1) {
        errmsg = "Couldn't set resource limit";
        goto err;
    }

    if (setenv("MALLOC_CHECK_", "7", 1) == -1) {
        errmsg = "Couldn't set environment variable";
        goto err;
    }

    return 0;

err:
    err = MINUS_ERRNO;
    error(0, errno, "%s", errmsg);
    return err;
}

static void
destroy_mount_data(struct mount_data *md)
{
    free(md->mountpoint);

    if (md->wd != -1)
        close(md->wd);
    if (md->db_pathname != NULL)
        free(md->db_pathname);
}

#define FLAG_MAP_ENTRY(fl, keep) {#fl, offsetof(struct mount_data, fl), keep}

static int
opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    size_t i;
    struct mount_data *md = data;

    static const struct ent {
        const char  *opt;
        size_t      optoff;
        int         keep;
    } flag_map[] = {
        FLAG_MAP_ENTRY(ro,      1),
        FLAG_MAP_ENTRY(lkw,     0),
        FLAG_MAP_ENTRY(fmtconv, 0),
        FLAG_MAP_ENTRY(debug,   0)
    };

    static const char *const filter_opts[] = {
        "nodev", "noexec", "nosuid", "rw", "user"
    };

    (void)outargs;

    if (key == FUSE_OPT_KEY_NONOPT) {
        if (md->mountpoint == NULL) {
            md->mountpoint = strdup(arg);
            return md->mountpoint == NULL ? -1 : 0;
        }
        return 1;
    }

    if (key != FUSE_OPT_KEY_OPT)
        return 1;

    for (i = 0; i < ARRAY_SIZE(flag_map); i++) {
        const struct ent *fl = &flag_map[i];

        if (strcmp(fl->opt, arg) == 0) {
            *(unsigned *)((char *)md + fl->optoff) = 1;
            return fl->keep;
        }
    }

    for (i = 0; i < ARRAY_SIZE(filter_opts); i++) {
        if (strcmp(filter_opts[i], arg) == 0)
            return 0;
    }

    return 1;
}

#undef FLAG_MAP_ENTRY

static int
do_fuse_parse_cmdline(struct fuse_args *args, char **mountpoint,
                      int *multithreaded, int *foreground)
{
    int ret;
#if FUSE_USE_VERSION == 32
    struct fuse_cmdline_opts opts;
#endif

#if FUSE_USE_VERSION != 32
    ret = fuse_parse_cmdline(args, mountpoint, multithreaded, foreground);
#else
    omemset(&opts, 0);
    ret = fuse_parse_cmdline(args, &opts);
#endif
    if (ret == -1)
        return ret;

#if FUSE_USE_VERSION == 32
    if (mountpoint != NULL)
        *mountpoint = opts.mountpoint;
    if (multithreaded != NULL)
        *multithreaded = !(opts.singlethread);
    if (foreground != NULL)
        *foreground = opts.foreground;

#endif
    return 0;
}

static int
parse_cmdline(struct fuse_args *args, struct fuse_data *fusedata)
{
    int err = -EINVAL, res;

    static const struct fuse_opt opts[] = {
        {"privs=%s",    offsetof(struct mount_data, creds),         0},
        {"-F %s",       offsetof(struct mount_data, db_pathname),   0},
        {"-p %d",       offsetof(struct mount_data, pipefd),        0},
        {"-u",          offsetof(struct mount_data, unmount),       1},
        FUSE_OPT_END
    };

    omemset(&fusedata->md, 0);
    fusedata->md.wd = fusedata->md.pipefd = -1;

    if (fuse_opt_parse(args, &fusedata->md, opts, &opt_proc) == -1)
        goto err1;

    if (fusedata->md.debug)
        fuse_cache_debug = 1;

    if (fusedata->md.pipefd != -1) {
        res = is_pipe(fusedata->md.pipefd);
        if (res != 1) {
            if (res != 0)
                err = res;
            goto err2;
        }
    }

    if (!fusedata->md.unmount
        && do_fuse_parse_cmdline(args, NULL, NULL, &fusedata->foreground) == -1)
        goto err2;

    if (fusedata->md.mountpoint == NULL) {
        error(0, 0, "Missing mountpoint parameter");
        goto err2;
    }
    fusedata->mountpoint = fusedata->md.mountpoint;

    return 0;

err2:
    if (fusedata->md.db_pathname != NULL)
        free(fusedata->md.db_pathname);
err1:
    fuse_opt_free_args(args);
    return err;
}

static int
set_privs(char *privs)
{
    char *ptr, *tmp;
    const char *grpname, *usrname;
    gid_t gid;
    int err;
    long val;
    struct group grp, *grpres;
    struct passwd pwd, *pwdres;
    uid_t uid;

    usrname = strtok_r(privs, ":", &ptr);
    if (usrname == NULL)
        return -EINVAL;
    grpname = strtok_r(NULL, ":", &ptr);
    if (grpname == NULL)
        return -EINVAL;

    errno = 0;
    val = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (val == -1) {
        if (errno != 0)
            return MINUS_ERRNO;
        val = 1024;
    }

    ptr = malloc(val);
    if (ptr == NULL)
        return MINUS_ERRNO;

    for (;;) {
        err = getpwnam_r(usrname, &pwd, ptr, val, &pwdres);
        if (!err)
            break;
        if (err != ERANGE) {
            err = -err;
            goto err;
        }

        val *= 2;
        tmp = realloc(ptr, val);
        if (tmp == NULL) {
            err = MINUS_ERRNO;
            goto err;
        }
        ptr = tmp;
    }
    if (pwdres == NULL) {
        err = -ENOENT;
        goto err;
    }
    uid = pwdres->pw_uid;

    for (;;) {
        err = getgrnam_r(grpname, &grp, ptr, val, &grpres);
        if (!err)
            break;
        if (err != ERANGE) {
            err = -err;
            goto err;
        }

        val *= 2;
        tmp = realloc(ptr, val);
        if (tmp == NULL) {
            err = MINUS_ERRNO;
            goto err;
        }
        ptr = tmp;
    }
    if (grpres == NULL) {
        err = -ENOENT;
        goto err;
    }
    gid = grpres->gr_gid;

    free(ptr);

    return setegid(gid) == -1 || seteuid(uid) == -1 ? MINUS_ERRNO : 0;

err:
    free(ptr);
    return err;
}

static struct fuse_session *
do_fuse_mount(const char *mountpoint, struct fuse_args *args,
              const struct fuse_lowlevel_ops *ops, size_t op_size,
              void *userdata, struct fuse_chan **ch)
{
#if FUSE_USE_VERSION == 32
    struct fuse_session *ret;

    (void)ch;

    ret = fuse_session_new(args, ops, op_size, userdata);
    if (ret == NULL)
        return NULL;

    if (fuse_session_mount(ret, mountpoint) == -1) {
        fuse_session_destroy(ret);
        return NULL;
    }

    return ret;
#else
    struct fuse_chan *chan;
    struct fuse_session *ret;

    chan = fuse_mount(mountpoint, args);
    if (chan == NULL)
        return NULL;

    ret = fuse_lowlevel_new(args, ops, op_size, userdata);
    if (ret == NULL) {
        fuse_unmount(mountpoint, chan);
        return NULL;
    }

    fuse_session_add_chan(ret, chan);

    *ch = chan;
    return ret;
#endif
}

static int
read_errpipe(int pipefd, const char **buf)
{
    size_t numread;
    ssize_t ret;
    static struct errpipe_msg msg;

    *buf = NULL;

    for (numread = 0;; numread += ret) {
        ret = read(pipefd, (char *)&msg + numread, sizeof(msg) - numread);
        if (ret < 1) {
            if (ret == 0)
                break;
            if (errno != EINTR)
                return MINUS_ERRNO;
            continue;
        }
    }

    if (numread < ERRPIPE_MIN_MSGLEN || numread != msg.msglen)
        return -EIO;

    if (msg.err)
        *buf = msg.buf;
    return msg.err;
}

static int
write_errpipe(int pipefd, int err, const char *buf)
{
    size_t len;
    ssize_t ret;
    struct errpipe_msg msg;

    msg.msglen = ERRPIPE_MIN_MSGLEN;
    if (buf == NULL)
        msg.err = 0;
    else {
        len = _strlcpy(msg.buf, buf, sizeof(msg.buf));
        if (len < sizeof(msg.buf)) {
            msg.err = err;
            msg.msglen += len;
        } else {
            msg.err = -EIO;
            ++msg.msglen;
            msg.buf[0] = '\0';
        }
    }

    for (len = 0; len < msg.msglen; len += ret) {
        ret = write(pipefd, (char *)&msg + len, msg.msglen - len);
        if (ret < 1) {
            if (ret == 0)
                break;
            if (errno != EINTR)
                return MINUS_ERRNO;
            continue;
        }
    }

    return 0;
}

static int
do_fuse_daemonize(pid_t *fspid)
{
    int dfd;
    int err;
    pid_t pid;

    pid = fork();
    if (pid == -1)
        return MINUS_ERRNO;

    if (pid != 0) {
        *fspid = pid;
        return 1;
    }

    dfd = open(".", O_DIRECTORY | OPEN_MODE_EXEC);
    if (dfd == -1)
        return MINUS_ERRNO;

    if (fuse_daemonize(0) == -1) {
        err = -EIO;
        goto err;
    }

    if (fchdir(dfd) == -1) {
        err = MINUS_ERRNO;
        goto err;
    }

    close(dfd);

    return 0;

err:
    close(dfd);
    return err;
}

static int
do_fuse_session_loop_mt(struct fuse_session *se)
{
#if FUSE_USE_VERSION == 32
    struct fuse_loop_config mtconf;

    mtconf.clone_fd = 0;
    mtconf.max_idle_threads = 10;

    return fuse_session_loop_mt(se, &mtconf);
#else
    return fuse_session_loop_mt(se);
#endif
}

/*
 * Note: The fuse_unmount() function is not reliable, as it can fail without
 * returning an error in at least the following scenarios:
 *
 * - It attempts to run the umount(1) program when the EUID is 0 and /etc/mtab
 *   is to be updated, but this fails because
 *   - either the fork() or execve() system call returns an error (such as
 *     EAGAIN or ENOMEM), or
 *   - the umount() system call returns ENOMEM in the umount(1) process
 * - It attempts to call umount2() directly when the EUID is 0 and /etc/mtab is
 *   not to be updated, and the system call returns ENOMEM
 * - It attempts to run the fusermount(1) program when the EUID is not 0 and
 *   - either the fork() or execve() system call returns an error (such as
 *     EAGAIN or ENOMEM), or
 *   - the umount2() system call returns ENOMEM in the fusermount(1) process
 *
 * Note that in the above scenarios, the device /dev/fuse is closed and hence
 * the FUSE connection is closed as well. This results in FUSE returning
 * ENOTCONN errors for any file system operation on the mount point, until it is
 * successfully unmounted. Later, this function may be updated to avoid the
 * close of /dev/fuse so that a failed unmount may be retried by the file system
 * process until successful.
 *
 * This function can be used when an error occurs during simplefs_init(). In
 * this case, only one worker thread is processing requests from /dev/fuse.
 * Hence, when the init request returns, all further request processing in user
 * space should immediately cease. At the same time, the completion of the init
 * request would permit the mount of the file system to complete and allow file
 * system calls in other processes to be serviced by the FUSE kernel module,
 * before the unmount of the file system can be started. However, this should
 * not lead to the umount() or umount2() system call returning EBUSY. This is
 * because any file system calls issued after the mount of the file system but
 * before the unmount operation is processed will be aborted by closing
 * /dev/fuse before proceeding with the unmount as described above. Thus, any
 * file system calls that are processed by the VFS in this window, as well as
 * any file system calls after an unmount that fails due to one of the reasons
 * mentioned above, should return with ENOTCONN.
 */
static void
do_fuse_unmount(const char *mountpoint, struct fuse_chan *ch,
                struct fuse_session *se)
{
#if FUSE_USE_VERSION == 32
    (void)mountpoint;
    (void)ch;

    fuse_session_unmount(se);
#else
    (void)se;

    fuse_unmount(mountpoint, ch);
#endif
}

/*
 * Note: This function does not execute fusermount directly, but executes
 * fusermount after forking a child process to enable more flexible usage.
 */
static int
do_unmount_path(const char *mountpoint)
{
    int status;
    pid_t pid;

    pid = fork();
    if (pid == -1)
        return MINUS_ERRNO;
    if (pid == 0) {
        execlp(FUSERMOUNT_PATH, FUSERMOUNT_PATH, "-u", mountpoint, NULL);
        _exit(EXIT_FAILURE);
    }

    if (waitpid(pid, &status, 0) == -1)
        return MINUS_ERRNO;

    return WIFEXITED(status) ? WEXITSTATUS(status) : -EIO;
}

static int
open_log(const char *mountpoint)
{
    static char buf[32+PATH_MAX];

    if (fmtbuf(buf, "simplefs:%s", mountpoint) != 0)
        return -ENAMETOOLONG;

    openlog(buf, LOG_PERROR | LOG_PID, LOG_USER);

    return 0;
}

static int
init_fuse(struct fuse_args *args, struct fuse_data *fusedata)
{
    char *bn, *dn;
    char buf[PATH_MAX];
    const char *errmsg;
    int background;
    int errpipe[2];
    int res = 0;
    int status;
    pid_t pid;

    if (fuse_opt_add_arg(args, "-o") == -1
        || fuse_opt_add_arg(args, DEFAULT_FUSE_OPTIONS) == -1)
        goto err1;

    dn = dirname_safe(fusedata->mountpoint, buf, sizeof(buf));
    if (dn == NULL) {
        res = -ENAMETOOLONG;
        errmsg = "Pathname too long";
        goto err1;
    }
    bn = strdup(basename_safe(fusedata->mountpoint));
    if (bn == NULL) {
        res = MINUS_ERRNO;
        goto err1;

    fusedata->mountpoint = bn;

    if (fusedata->md.db_pathname == NULL
        || fusedata->md.db_pathname[0] != '/') {
        errmsg = "Error opening directory";
        fusedata->md.wd = open(".", O_CLOEXEC | O_DIRECTORY | O_RDONLY);
        if (fusedata->md.wd == -1) {
            if (OPEN_MODE_EXEC == O_RDONLY || errno != EACCES) {
                res = MINUS_ERRNO;
                goto err1;
            }
            /* retry open with search permissions only */
            fusedata->md.wd = open(".",
                                   O_CLOEXEC | O_DIRECTORY | OPEN_MODE_EXEC);
            if (fusedata->md.wd == -1) {
                res = MINUS_ERRNO;
                goto err1;
            }
        }
    }

    if (chdir(dn) == -1) {
        res = MINUS_ERRNO;
        errmsg = "Error changing directory";
        goto err2;
    }

    errmsg = "Error initializing FUSE file system";

    res = request_new(&fusedata->ctx, REQUEST_DEFAULT, REPLY_DEFAULT,
                      &fusedata->md, &sess_default_ops, fusedata);
    if (res != 0)
        goto err2;

    background = !fusedata->foreground;

    if (background) {
        if (pipe(errpipe) == -1) {
            res = MINUS_ERRNO;
            goto err3;
        }

        res = do_fuse_daemonize(&pid);
        if (res == 1) {
            close(errpipe[1]);
            goto parent_end;
        }
        close(errpipe[0]);
        if (res != 0)
            goto err4;
    }

    res = request_fuse_init_prepare(fusedata->ctx);
    if (res != 0)
        goto err4;

    fusedata->sess = do_fuse_mount(fusedata->mountpoint, args,
                                   &request_fuse_ops, sizeof(request_fuse_ops),
                                   fusedata->ctx, &fusedata->chan);
    if (fusedata->sess == NULL) {
        res = -EIO;
        errmsg = "Error mounting FUSE file system";
        if (background)
            write_errpipe(errpipe[1], res, errmsg);
        goto err5;
    }

    if (background) {
        res = write_errpipe(errpipe[1], 0, NULL);
        close(errpipe[1]);
        if (res != 0)
            goto err6;
    }

    fusedata->aborted = 0;

    syslog(LOG_INFO, FSNAME " using " LIBNAME " initialized successfully");

    return 0;

parent_end:
    res = read_errpipe(errpipe[0], &errmsg);
    close(errpipe[0]);
    if (res != 0) {
        waitpid(pid, &status, 0);
        if (errmsg == NULL)
            errmsg = "Error mounting FUSE file system";
        goto err3;
    }
    request_end(fusedata->ctx);
    if (fusedata->md.wd != -1)
        close(fusedata->md.wd);
    if (fusedata->mountpoint != fusedata->md.mountpoint)
        free(fusedata->mountpoint);
    return 1;

err6:
    do_fuse_unmount(fusedata->mountpoint, fusedata->chan, fusedata->sess);
    fuse_session_destroy(fusedata->sess);
err5:
    request_fuse_destroy_finish(fusedata->ctx);
err4:
    if (background)
        close(errpipe[1]);
err3:
    request_end(fusedata->ctx);
err2:
    if (fusedata->md.wd != -1)
        close(fusedata->md.wd);
err1:
    if (fusedata->mountpoint != fusedata->md.mountpoint)
        free(fusedata->mountpoint);
    if (res == 0) {
        res = -ENOMEM;
        errmsg = "Out of memory";
    }
    error(0, -res, "%s", errmsg);
    return res;
}

static int
process_fuse_events(struct fuse_data *fusedata)
{
    if (do_fuse_session_loop_mt(fusedata->sess) == -1) {
        error(0, 0, "Error mounting FUSE file system");
        return -EIO;
    }

    return 0;
}

static int
terminate_fuse(struct fuse_data *fusedata)
{
    int ret;

    if (fusedata->aborted)
        do_fuse_unmount(fusedata->mountpoint, fusedata->chan, fusedata->sess);
    fuse_session_destroy(fusedata->sess);

    ret = request_fuse_destroy_finish(fusedata->ctx);
    if (ret == 0)
        syslog(LOG_INFO, FSNAME " terminated successfully");
    else
        syslog(LOG_ERR, FSNAME " terminated with error");

    request_end(fusedata->ctx);

    return ret;
}

static int
unmount_fuse(struct fuse_data *fusedata)
{
    int ret;

    ret = do_unmount_path(fusedata->mountpoint);
    if (ret != 0)
        error(0, -ret, "Error unmounting FUSE file system");

    return ret;
}

int
main(int argc, char **argv)
{
    int ret, status, tmp;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_data fusedata;

    ret = parse_cmdline(&args, &fusedata);
    if (ret != 0)
        error(EXIT_FAILURE, -ret, "Error parsing command line");

    if (fusedata.md.creds != NULL) {
        ret = set_privs(fusedata.md.creds);
        free(fusedata.md.creds);
        if (ret != 0)
            error(EXIT_FAILURE, -ret, "Error setting privileges");
    }

    if (enable_debugging_features() != 0)
        goto err1;

    if (set_up_signal_handlers() != 0)
        goto err1;

    if (fusedata.md.pipefd != -1) {
        ret = set_cloexec(fusedata.md.pipefd);
        if (ret != 0)
            goto err1;
    }

    if (fusedata.md.unmount) {
        fuse_opt_free_args(&args);
        status = unmount_fuse(&fusedata) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        goto end;
    }

    if (open_log(fusedata.md.mountpoint) != 0)
        goto err1;

    ret = init_fuse(&args, &fusedata);
    if (ret != 0) {
        if (ret != 1)
            goto err2;
        goto parent_end;
    }

    fuse_opt_free_args(&args);

    ret = process_fuse_events(&fusedata);

    tmp = terminate_fuse(&fusedata);
    if (tmp != 0)
        ret = tmp;

    if (ret == 0) {
        status = EXIT_SUCCESS;
        syslog(LOG_INFO, "Returned success status");
    } else {
        status = EXIT_FAILURE;
        syslog(LOG_ERR, "Returned failure status");
    }

    free(fusedata.mountpoint);

    closelog();

end:
    destroy_mount_data(&fusedata.md);
    return status;

parent_end:
    closelog();
    destroy_mount_data(&fusedata.md);
    fuse_opt_free_args(&args);
    return EXIT_SUCCESS;

err2:
    closelog();
err1:
    destroy_mount_data(&fusedata.md);
    fuse_opt_free_args(&args);
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
