/*
 * mount.simplefs.c
 */

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#define SIMPLEFS_PATH "simplefs"
#define SIMPLEFS_MOUNT_OPTS "allow_other,nonempty"

#define SIMPLEFS_MOUNT_PIPE_FD 4

static int parse_cmdline(int, char **, int *, char ***);

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

int
main(int argc, char **argv)
{
    char buf[2];
    char **mount_argv;
    int mount_argc;
    int mountpoint;
    int pipefd[2];
    int status;
    pid_t pid;
    size_t numread, toread;
    ssize_t ret;

    if (parse_cmdline(argc, argv, &mount_argc, &mount_argv) == -1)
        return EXIT_FAILURE;

    mount_argv[0] = "mount";
    mountpoint = 2;

    pid = fork();
    if (pid == -1)
        goto mnt_err;
    if (pid == 0) {
        if (execvp("mount", mount_argv) == -1)
            goto mnt_err;
        exit(EXIT_FAILURE);
    }

    if (waitpid(pid, &status, 0) == -1)
        goto mnt_err;
    if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0))
        error(EXIT_FAILURE, 0, "Mounting failed");

    if (chdir(mount_argv[mountpoint]) == -1)
        error(EXIT_FAILURE, errno, "Error changing directory");

    if (pipe(pipefd) == -1)
        goto fs_err;
    if (pipefd[1] != SIMPLEFS_MOUNT_PIPE_FD) {
        if (dup2(pipefd[1], SIMPLEFS_MOUNT_PIPE_FD) == -1)
            goto fs_err;
        close(pipefd[1]);
    }

    pid = fork();
    if (pid == -1)
        goto fs_err;
    if (pid == 0) {
        if (execlp(SIMPLEFS_PATH, SIMPLEFS_PATH, "-f", "-o",
                   SIMPLEFS_MOUNT_OPTS, ".", NULL) == -1)
            goto fs_err;
        exit(EXIT_FAILURE);
    }

    close(SIMPLEFS_MOUNT_PIPE_FD);

    toread = sizeof(buf);
    for (numread = 0; numread < toread; numread += ret) {
        ret = read(pipefd[0], buf + numread, toread);
        if (ret == -1)
            goto fs_err;
        if (ret == 0) {
            waitpid(pid, &status, 0);
            error(EXIT_FAILURE, 0, "Mounting failed");
        }
        toread -= ret;
    }
    if (strcmp(buf, "1") != 0)
        error(EXIT_FAILURE, 0, "Mounting failed");

    return EXIT_SUCCESS;

fs_err:
    error(EXIT_FAILURE, errno, "Error executing simplefs");
    return EXIT_FAILURE;

mnt_err:
    error(EXIT_FAILURE, errno, "Error executing mount");
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
