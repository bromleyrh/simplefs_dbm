/*
 * simplefs.c
 */

#include "common.h"
#include "ops.h"
#include "simplefs.h"

#include <fuse.h>
#include <fuse_lowlevel.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

#include <sys/resource.h>

struct fuse_data {
    const char          *mountpoint;
    int                 foreground;
    struct mount_data   md;
    struct fuse_chan    *chan;
    struct fuse_session *sess;
};

static int enable_debugging_features(void);

static int parse_cmdline(struct fuse_args *, struct fuse_data *);

static int init_fuse(int, char **, struct fuse_data *);
static int process_fuse_events(struct fuse_data *);
static void terminate_fuse(struct fuse_data *);

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
        {"ro", offsetof(struct mount_data, ro), 1},
        FUSE_OPT_END
    };

    if (fuse_parse_cmdline(args, (char **)&fusedata->mountpoint, NULL,
                           &fusedata->foreground)
        == -1)
        return -EINVAL;

    fusedata->md.mountpoint = fusedata->mountpoint;

    fusedata->md.ro = 0;

    return (fuse_opt_parse(args, &fusedata->md, opts, NULL) == -1)
           ? -EINVAL : 0;
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

    err = -EIO;
    errmsg = "Error mounting FUSE file system";

    fusedata->chan = fuse_mount(fusedata->mountpoint, &args);
    if (fusedata->chan == NULL)
        goto err2;

    if (fuse_set_signal_handlers(fusedata->sess) == -1)
        goto err3;

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
    free((void *)(fusedata->mountpoint));
err1:
    fuse_opt_free_args(&args);
    error(0, -err, "%s", errmsg);
    return err;
}

static int
process_fuse_events(struct fuse_data *fusedata)
{
    if (!(fusedata->foreground) && (fuse_daemonize(0) == -1))
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
    fuse_session_destroy(fusedata->sess);

    fuse_unmount(fusedata->mountpoint, fusedata->chan);

    free((void *)(fusedata->mountpoint));
}

int
main(int argc, char **argv)
{
    int status;
    struct fuse_data fusedata;

    if (enable_debugging_features() != 0)
        return EXIT_FAILURE;

    if (init_fuse(argc, argv, &fusedata) != 0)
        return EXIT_FAILURE;

    status = EXIT_FAILURE;

    if (process_fuse_events(&fusedata) == 0)
        status = EXIT_SUCCESS;

    terminate_fuse(&fusedata);

    return status;
}

/* vi: set expandtab sw=4 ts=4: */
