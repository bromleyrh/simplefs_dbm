/*
 * mount.simplefs.c
 */

#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MOUNT_DEVICE_ARGV_IDX 1
#define MOUNT_MOUNTPOINT_ARGV_IDX 2

#define SIMPLEFS_PATH "simplefs"
#define SIMPLEFS_MOUNT_OPTS "allow_other,nonempty"

#define SIMPLEFS_MOUNT_PIPE_FD 4
#define SIMPLEFS_MOUNT_PIPE_MSG_OK "1"

static int parse_cmdline(int, char **, int, int *, char ***);

static int do_mount(char **, int);

static int open_simplefs_pipe(int);
static int read_simplefs_pipe(int);

static int redirect_std_fds(const char *);

static int do_start_simplefs(char **, sigset_t *);

static int
parse_cmdline(int argc, char **argv, int file_based, int *mount_argc,
              char ***mount_argv)
{
    char **mnt_argv;

    if (file_based) {
        mnt_argv = calloc(argc + 1, sizeof(*mnt_argv));
        if (mnt_argv == NULL)
            return -1;

        memcpy(mnt_argv, argv, argc * sizeof(char *));
    } else {
        char *optstr = NULL;
        int i;

        for (i = MOUNT_MOUNTPOINT_ARGV_IDX + 1; i < argc - 1; i++) {
            if (strcmp("-o", argv[i]) == 0) {
                optstr = argv[i+1];
                break;
            }
        }

        argc = 5;
        if (optstr != NULL)
            argc += 2;

        mnt_argv = calloc(argc, sizeof(*mnt_argv));
        if (mnt_argv == NULL)
            return -1;

        mnt_argv[0] = argv[0];
        mnt_argv[1] = "-F";
        mnt_argv[2] = argv[MOUNT_DEVICE_ARGV_IDX];

        i = 3;
        if (optstr != NULL) {
            mnt_argv[i++] = "-o";
            mnt_argv[i++] = optstr;
        }

        mnt_argv[i] = argv[MOUNT_MOUNTPOINT_ARGV_IDX];
    }

    *mount_argc = argc;
    *mount_argv = mnt_argv;
    return 0;
}

static int
do_mount(char **argv, int unmount)
{
    int status;
    pid_t pid;

    pid = fork();
    if (pid == -1)
        return MINUS_ERRNO;
    if (pid == 0) {
        char **argvp, *umount_argv[4];

        if (unmount) {
            umount_argv[0] = "umount";
            umount_argv[1] = "-l";
            umount_argv[2] = ".";
            umount_argv[3] = NULL;
            argvp = umount_argv;
        } else {
            argv[0] = "mount";
            argvp = argv;
        }
        execvp(argvp[0], argvp);
        exit(EXIT_FAILURE);
    }

    if (waitpid(pid, &status, 0) == -1)
        return MINUS_ERRNO;

    return WIFEXITED(status) ? WEXITSTATUS(status) : -EIO;
}

static int
open_simplefs_pipe(int fd)
{
    int pipefd[2];

    if (pipe(pipefd) == -1)
        return MINUS_ERRNO;

    if (pipefd[1] != fd) {
        if (dup2(pipefd[1], fd) == -1)
            return MINUS_ERRNO;
        close(pipefd[1]);
    }

    return pipefd[0];
}

static int
read_simplefs_pipe(int pipefd)
{
    char buf[2];
    size_t numread, toread;
    ssize_t ret;

    toread = sizeof(buf);
    for (numread = 0; numread < toread; numread += ret) {
        ret = read(pipefd, buf + numread, toread);
        if (ret == -1)
            return MINUS_ERRNO;
        if (ret == 0)
            return 2;
        toread -= ret;
    }

    return (strcmp(buf, SIMPLEFS_MOUNT_PIPE_MSG_OK) != 0);
}

static int
redirect_std_fds(const char *path)
{
    int err;
    int fd;

    fd = open(path, O_RDWR);
    if (fd == -1)
        return MINUS_ERRNO;

    if ((dup2(fd, STDIN_FILENO) == -1) || (dup2(fd, STDOUT_FILENO) == -1)
        || (dup2(fd, STDERR_FILENO) == -1))
        err = MINUS_ERRNO;
    else
        err = 0;

    close(fd);

    return err;
}

static int
do_start_simplefs(char **mount_argv, sigset_t *set)
{
    int err;
    int pipefd;
    int status;
    pid_t pid;

    pipefd = open_simplefs_pipe(SIMPLEFS_MOUNT_PIPE_FD);
    if (pipefd < 0)
        return pipefd;

    pid = fork();
    if (pid == -1)
        return MINUS_ERRNO;
    if (pid == 0) {
        if ((sigprocmask(SIG_SETMASK, set, NULL) != 0)
            || (redirect_std_fds("/dev/null") != 0) || (setsid() == -1))
            exit(EXIT_FAILURE);
        if (mount_argv == NULL) {
            execlp(SIMPLEFS_PATH, SIMPLEFS_PATH, "-f", "-o",
                   SIMPLEFS_MOUNT_OPTS, ".", NULL);
        } else {
            mount_argv[0] = "simplefs";
            execvp(SIMPLEFS_PATH, mount_argv);
        }
        exit(EXIT_FAILURE);
    }

    close(SIMPLEFS_MOUNT_PIPE_FD);

    err = read_simplefs_pipe(pipefd);
    if (err > 0) {
        waitpid(pid, &status, 0);
        return 1;
    }

    return err;
}

int
main(int argc, char **argv)
{
    char buf[PATH_MAX];
    char **mount_argv;
    const char *errmsg = "Mounting failed";
    const char *mountpoint;
    int err;
    int file_based;
    int mount_argc;
    sigset_t oset, set;

    if (snprintf(buf, sizeof(buf), "%s", argv[0]) >= (int)sizeof(buf))
        return EXIT_FAILURE;
    file_based = (strcmp("mount.simplefs-file", basename(buf)) == 0);

    if (parse_cmdline(argc, argv, file_based, &mount_argc, &mount_argv) == -1)
        return EXIT_FAILURE;

    mountpoint = mount_argv[MOUNT_MOUNTPOINT_ARGV_IDX];

    if (file_based) {
        if (snprintf(buf, sizeof(buf), "%s", mountpoint) >= (int)sizeof(buf)) {
            err = -ENAMETOOLONG;
            errmsg = "Path argument too long";
            goto err1;
        }
        if (chdir(dirname(buf)) == -1) {
            err = -errno;
            errmsg = "Error changing directory";
            goto err1;
        }

        snprintf(buf, sizeof(buf), "%s", mountpoint);
        mountpoint = mount_argv[MOUNT_MOUNTPOINT_ARGV_IDX] = basename(buf);
    }

    if ((sigfillset(&set) != 0)
        || (sigprocmask(SIG_BLOCK, &set, &oset) == -1)) {
        free(mount_argv);
        return EXIT_FAILURE;
    }

    if (file_based) {
        err = do_mount(mount_argv, 0);
        if (err)
            goto err1;

        if (chdir(mountpoint) == -1) {
            err = MINUS_ERRNO;
            goto err2;
        }
    }

    err = do_start_simplefs(file_based ? NULL : mount_argv, &oset);
    if (err) {
        errmsg = "Error executing simplefs";
        if (file_based)
            goto err2;
        goto err1;
    }

    free(mount_argv);

    return EXIT_SUCCESS;

err2:
    do_mount(mount_argv, 1);
err1:
    free(mount_argv);
    error(EXIT_FAILURE, (err > 0) ? EIO : -err, "%s", errmsg);
}

/* vi: set expandtab sw=4 ts=4: */
