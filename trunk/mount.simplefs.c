/*
 * mount.simplefs.c
 */

#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MOUNT_MOUNTPOINT_ARGV_IDX 2

#define SIMPLEFS_PATH "simplefs"
#define SIMPLEFS_MOUNT_OPTS "allow_other,nonempty"

#define SIMPLEFS_MOUNT_PIPE_FD 4
#define SIMPLEFS_MOUNT_PIPE_MSG_OK "1"

static int parse_cmdline(int, char **, int *, char ***);

static int do_mount(char **);

static int open_simplefs_pipe(int);
static int read_simplefs_pipe(int);

static int redirect_std_fds(const char *);

static int do_start_simplefs(const char *);

static int
parse_cmdline(int argc, char **argv, int *mount_argc, char ***mount_argv)
{
    char **mnt_argv;

    mnt_argv = calloc(argc, sizeof(*mnt_argv));
    if (mnt_argv == NULL)
        return -1;

    memcpy(mnt_argv, argv, argc * sizeof(char *));

    *mount_argc = argc;
    *mount_argv = mnt_argv;
    return 0;
}

static int
do_mount(char **argv)
{
    int status;
    pid_t pid;

    pid = fork();
    if (pid == -1)
        return MINUS_ERRNO;
    if (pid == 0) {
        argv[0] = "mount";
        execvp("mount", argv);
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
do_start_simplefs(const char *mountpoint)
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
        if ((chdir(mountpoint) == 0) && (redirect_std_fds("/dev/null") == 0)
            && (setsid() != -1)) {
            execlp(SIMPLEFS_PATH, SIMPLEFS_PATH, "-f", "-o",
                   SIMPLEFS_MOUNT_OPTS, ".", NULL);
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
    char **mount_argv;
    const char *errmsg;
    int err;
    int mount_argc;

    if (parse_cmdline(argc, argv, &mount_argc, &mount_argv) == -1)
        return EXIT_FAILURE;

    err = do_mount(mount_argv);
    if (err) {
        errmsg = "Mounting failed";
        goto err;
    }

    err = do_start_simplefs(mount_argv[MOUNT_MOUNTPOINT_ARGV_IDX]);
    if (err) {
        errmsg = "Error executing simplefs";
        goto err;
    }

    return EXIT_SUCCESS;

err:
    error(EXIT_FAILURE, (err > 0) ? EIO : -err, "%s", errmsg);
}

/* vi: set expandtab sw=4 ts=4: */
