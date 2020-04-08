/*
 * simplefs.c
 */

#include "ops.h"
#include "simplefs.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <forensics.h>

#include <fuse.h>
#include <fuse_lowlevel.h>

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/resource.h>

struct fuse_data {
    const char          *mountpoint;
    int                 foreground;
    struct mount_data   md;
    struct fuse_chan    *chan;
    struct fuse_session *sess;
};

static struct fuse_session *sess;

static void int_handler(int);

static int set_up_signal_handlers(void);

static int enable_debugging_features(void);

static int opt_proc(void *, const char *, int, struct fuse_args *);
static int do_fuse_parse_cmdline(struct fuse_args *, char **, int *, int *);
static int parse_cmdline(struct fuse_args *, struct fuse_data *);

static struct fuse_session *do_fuse_mount(const char *, struct fuse_args *,
                                          const struct fuse_lowlevel_ops *,
                                          size_t, void *, struct fuse_chan **);
static int do_fuse_daemonize(void);
static int do_fuse_session_loop_mt(struct fuse_session *);
static void do_fuse_unmount(const char *, struct fuse_chan *,
                            struct fuse_session *);

static int init_fuse(int, char **, struct fuse_data *);
static int process_fuse_events(struct fuse_data *);
static void terminate_fuse(struct fuse_data *);

static int open_log(const char *);

#ifdef __linux__
#define DEFAULT_FUSE_OPTIONS "auto_unmount,default_permissions"
#else
#define DEFAULT_FUSE_OPTIONS "default_permissions"
#endif

static void
int_handler(int signum)
{
    (void)signum;
}

static int
set_up_signal_handlers()
{
    static const struct sigaction sa_term = {
        .sa_handler = &int_handler
    }, sa_pipe = {
        .sa_handler = SIG_IGN
    };

    return ((sigaction(SIGINT, &sa_term, NULL) == -1)
            || (sigaction(SIGTERM, &sa_term, NULL) == -1)
            || (sigaction(SIGHUP, &sa_pipe, NULL) == -1)
            || (sigaction(SIGPIPE, &sa_pipe, NULL) == -1))
           ? -errno : 0;
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

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigaction_segv_diag;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
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
    err = -errno;
    error(0, errno, "%s", errmsg);
    return err;
}

static int
opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    struct mount_data *md = (struct mount_data *)data;

    (void)outargs;

    if ((key == FUSE_OPT_KEY_OPT) && (strcmp("ro", arg) == 0))
        md->ro = 1;

    return 1;
}

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
    memset(&opts, 0, sizeof(opts));
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
    static const struct fuse_opt opts[] = {
        {"-F %s",   offsetof(struct mount_data, db_pathname),   0},
        FUSE_OPT_END
    };

    fusedata->md.db_pathname = NULL;
    fusedata->md.ro = 0;

    if (fuse_opt_parse(args, &fusedata->md, opts, &opt_proc) == -1)
        goto err1;

    if (do_fuse_parse_cmdline(args, (char **)&fusedata->mountpoint, NULL,
                              &fusedata->foreground)
        == -1)
        goto err2;

    if (fusedata->mountpoint == NULL) {
        error(0, 0, "Missing mountpoint parameter");
        goto err2;
    }

    fusedata->md.mountpoint = fusedata->mountpoint;

    return 0;

err2:
    if (fusedata->md.db_pathname != NULL)
        free((void *)(fusedata->md.db_pathname));
err1:
    return -EINVAL;
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
do_fuse_daemonize()
{
    int dfd;
    int err;

    dfd = open(".", O_DIRECTORY | O_RDONLY);
    if (dfd == -1)
        return -errno;

    if (fuse_daemonize(0) == -1) {
        err = -EIO;
        goto err;
    }

    if (fchdir(dfd) == -1) {
        err = -errno;
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

static void
do_fuse_unmount(const char *mountpoint, struct fuse_chan *ch,
                struct fuse_session *se)
{
#if FUSE_USE_VERSION == 32
    (void)mountpoint;
    (void)ch;

    return fuse_session_unmount(se);
#else
    (void)se;

    return fuse_unmount(mountpoint, ch);
#endif
}

static int
init_fuse(int argc, char **argv, struct fuse_data *fusedata)
{
    const char *errmsg;
    int err;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    err = parse_cmdline(&args, fusedata);
    if (err) {
        errmsg = "Error parsing command line";
        goto err1;
    }

    if ((fuse_opt_add_arg(&args, "-o") == -1)
        || (fuse_opt_add_arg(&args, DEFAULT_FUSE_OPTIONS)
            == -1)) {
        err = -ENOMEM;
        errmsg = "Out of memory";
        goto err2;
    }

    fusedata->sess = do_fuse_mount(fusedata->mountpoint, &args, &simplefs_ops,
                                   sizeof(simplefs_ops), &fusedata->md,
                                   &fusedata->chan);
    if (fusedata->sess == NULL) {
        err = -EIO;
        errmsg = "Error mounting FUSE file system";
        goto err2;
    }

    fuse_opt_free_args(&args);

    return 0;

err2:
    fuse_opt_free_args(&args);
    free((void *)(fusedata->mountpoint));
    if (fusedata->md.db_pathname != NULL)
        free((void *)(fusedata->md.db_pathname));
err1:
    error(0, -err, "%s", errmsg);
    return err;
}

static int
process_fuse_events(struct fuse_data *fusedata)
{
    if (!(fusedata->foreground) && (do_fuse_daemonize() == -1))
        goto err;

    if (do_fuse_session_loop_mt(fusedata->sess) == -1)
        goto err;

    return 0;

err:
    error(0, 0, "Error mounting FUSE file system");
    return -EIO;
}

static void
terminate_fuse(struct fuse_data *fusedata)
{
    do_fuse_unmount(fusedata->mountpoint, fusedata->chan, fusedata->sess);

    fuse_session_destroy(fusedata->sess);

    free((void *)(fusedata->mountpoint));
}

static int
open_log(const char *mountpoint)
{
    static char buf[32+PATH_MAX];

    if (snprintf(buf, sizeof(buf), "simplefs:%s", mountpoint)
        >= (int)sizeof(buf))
        return -ENAMETOOLONG;

    openlog(buf, LOG_PERROR | LOG_PID, LOG_USER);

    return 0;
}

void
simplefs_exit()
{
    fuse_session_exit(sess);
}

int
main(int argc, char **argv)
{
    int ret, status;
    struct fuse_data fusedata;

    if (enable_debugging_features() != 0)
        return EXIT_FAILURE;

    if (set_up_signal_handlers() == -1)
        return EXIT_FAILURE;

    if (init_fuse(argc, argv, &fusedata) != 0)
        return EXIT_FAILURE;

    if (open_log(fusedata.mountpoint) != 0)
        return EXIT_FAILURE;

    status = EXIT_FAILURE;

    sess = fusedata.sess;

    ret = process_fuse_events(&fusedata);

    terminate_fuse(&fusedata);

    if ((ret == 0) && (mount_status() == 0))
        status = EXIT_SUCCESS;

    if (fusedata.md.db_pathname != NULL)
        free((void *)(fusedata.md.db_pathname));

    if (status == EXIT_SUCCESS)
        syslog(LOG_INFO, "Returned success status");
    else
        syslog(LOG_ERR, "Returned failure status");

    closelog();

    return status;
}

/* vi: set expandtab sw=4 ts=4: */
