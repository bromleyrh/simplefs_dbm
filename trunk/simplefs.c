/*
 * simplefs.c
 */

#include "ops.h"
#include "simplefs.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <fuse.h>
#include <fuse_lowlevel.h>

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/resource.h>

struct fuse_data {
    const char          *mountpoint;
    int                 foreground;
    struct mount_data   md;
    struct fuse_chan    *chan;
    struct fuse_session *sess;
};

static void int_handler(int);

static int set_up_signal_handlers(void);

static int enable_debugging_features(void);

static int parse_cmdline(struct fuse_args *, struct fuse_data *);

static int do_fuse_daemonize(void);

static int init_fuse(int, char **, struct fuse_data *);
static int process_fuse_events(struct fuse_data *);
static void terminate_fuse(struct fuse_data *);

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

    static const struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY
    };

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
parse_cmdline(struct fuse_args *args, struct fuse_data *fusedata)
{
    static const struct fuse_opt opts[] = {
        {"-F %s",   offsetof(struct mount_data, db_pathname),   0},
        {"ro",      offsetof(struct mount_data, ro),            1},
        FUSE_OPT_END
    };

    fusedata->md.db_pathname = NULL;
    fusedata->md.ro = 0;

    if (fuse_opt_parse(args, &fusedata->md, opts, NULL) == -1)
        return -EINVAL;

    if (fuse_parse_cmdline(args, (char **)&fusedata->mountpoint, NULL,
                           &fusedata->foreground)
        == -1) {
        if (fusedata->md.db_pathname != NULL)
            free((void *)(fusedata->md.db_pathname));
        return -EINVAL;
    }

    fusedata->md.mountpoint = fusedata->mountpoint;

    return 0;
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
        || (fuse_opt_add_arg(&args, "auto_unmount,default_permissions")
            == -1)) {
        errmsg = "Out of memory";
        goto err2;
    }

    err = -EIO;
    errmsg = "Error mounting FUSE file system";

    fusedata->chan = fuse_mount(fusedata->mountpoint, &args);
    if (fusedata->chan == NULL)
        goto err2;

    fusedata->sess = fuse_lowlevel_new(&args, &simplefs_ops,
                                       sizeof(simplefs_ops), &fusedata->md);
    if (fusedata->sess == NULL)
        goto err3;

    fuse_session_add_chan(fusedata->sess, fusedata->chan);

    fuse_opt_free_args(&args);

    return 0;

err3:
    fuse_unmount(fusedata->mountpoint, fusedata->chan);
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
do_fuse_daemonize()
{
    char cwd[PATH_MAX];
    int dfd;
    int err;

    if (getcwd(cwd, sizeof(cwd)) == NULL)
        return -errno;

    dfd = open(cwd, O_DIRECTORY | O_RDONLY);
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
process_fuse_events(struct fuse_data *fusedata)
{
    if (!(fusedata->foreground) && (do_fuse_daemonize() == -1))
        goto err;

    if (fuse_session_loop_mt(fusedata->sess) == -1)
        goto err;

    return 0;

err:
    error(0, 0, "Error mounting FUSE file system");
    return -EIO;
}

static void
terminate_fuse(struct fuse_data *fusedata)
{
    fuse_unmount(fusedata->mountpoint, fusedata->chan);

    fuse_session_destroy(fusedata->sess);

    free((void *)(fusedata->mountpoint));
}

int
main(int argc, char **argv)
{
    int status;
    struct fuse_data fusedata;

    if (enable_debugging_features() != 0)
        return EXIT_FAILURE;

    if (set_up_signal_handlers() == -1)
        return EXIT_FAILURE;

    if (init_fuse(argc, argv, &fusedata) != 0)
        return EXIT_FAILURE;

    status = EXIT_FAILURE;

    if ((process_fuse_events(&fusedata) == 0) && (mount_status() == 0))
        status = EXIT_SUCCESS;

    terminate_fuse(&fusedata);

    if (fusedata.md.db_pathname != NULL)
        free((void *)(fusedata.md.db_pathname));

    return status;
}

/* vi: set expandtab sw=4 ts=4: */
