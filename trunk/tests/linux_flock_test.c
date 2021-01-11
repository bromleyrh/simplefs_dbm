/*
 * linux_flock_test.c
 *
 * Linux kernel version 4.9.24 (possibly along with other versions) contains a
 * race condition, where the system call flock(fd, LOCK_SH|EX | LOCK_NB) can
 * fail with errno == EAGAIN, if fd refers to a block device file and the block
 * device file had been recently closed, even if the close() was performed by
 * the same process and no locks were taken on the block device file. The
 * flock() call above succeeds after waiting for a short time (no more than one
 * or two seconds) after the EAGAIN error. On the other hand, if the block
 * device file is not opened and closed first (neither within the same process
 * nor in another process), the EAGAIN error does not occur.
 *
 * The problem can be addressed by only opening a block device file once in any
 * application, followed by calling flock(fd, LOCK_SH|EX | LOCK_NB). This issue
 * is currently worked around in simplefs by waiting for up to 10 seconds after
 * the first EAGAIN error when locking a block device file.
 *
 * This program demonstrates this race condition by intermittently outputting an
 * error, "Error locking <file>: Resource temporarily unavailable", when run
 * with a block device file argument. To reproduce the error, a shell loop such
 * as
 *
 * while ./linux_flock_test /dev/loop0; do
 *     true
 * done
 *
 * can be used. The shell loop
 *
 * while ./linux_flock_test /dev/loop0 1; do
 *     sleep 1
 * done
 *
 * demonstrates that the error is unlikely to occur when the block device is
 * closed at least one second before calling flock().
 */

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

static int open_file(const char *);
static void close_file(int);

static int
open_file(const char *pathname)
{
    int ret;

    ret = open(pathname, O_RDWR);
    if (ret == -1)
        error(EXIT_FAILURE, errno, "Error opening %s", pathname);

    return ret;
}

static void
close_file(int fd)
{
    if (close(fd) == -1)
        error(EXIT_FAILURE, errno, "Error closing file");
}

int
main(int argc, char **argv)
{
    const char *file;
    int err = 0;
    int fd;
    int num_opens;

    if (argc < 2)
        error(EXIT_FAILURE, 0, "Must specify file");
    file = argv[1];
    num_opens = ((argc > 2) && (strcmp("1", argv[2]) == 0)) ? 1 : 2;

    if (num_opens > 1)
        close_file(open_file(file));

    fd = open_file(file);

    if (flock(fd, LOCK_EX | LOCK_NB) == -1)
        err = errno;

    close(fd);

    if (err)
        error(EXIT_FAILURE, err, "Error locking %s", file);

    return EXIT_SUCCESS;
}

