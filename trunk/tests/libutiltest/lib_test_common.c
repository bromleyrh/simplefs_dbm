/*
 * lib_test_common.c
 */

#define _GNU_SOURCE

#include "util_test_common.h"

#include <strings_ext.h>

#include <files/acc_ctl.h>
#include <files/util.h>

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#define TEMP_SUFFIX "XXXXXX"
#define TEMP_SUFFIX_CHARS (sizeof(TEMP_SUFFIX) - 1)

#define DIR_OPEN_FLAGS (O_CLOEXEC | O_DIRECTORY | O_RDONLY)

static int get_template(char *, const char *);

static int
get_template(char *buf, const char *template)
{
    char *prevstate, state[256];
    size_t len;
    size_t i;

    static const char chars[62]
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    len = strlcpy(buf, template, PATH_MAX);
    if (len >= PATH_MAX)
        return -ENAMETOOLONG;

    if (strcmp(buf + len - TEMP_SUFFIX_CHARS, TEMP_SUFFIX) != 0)
        return -EINVAL;

    prevstate = initstate(time(NULL) + getpid(), state, sizeof(state));

    for (i = TEMP_SUFFIX_CHARS; i > 0; i--)
        buf[len - i] = chars[random() % sizeof(chars)];

    setstate(prevstate);

    return 0;
}

int
change_to_tmpdir(const char *template)
{
    char templ[PATH_MAX], *tmp;
    int dfd, fd;
    int err;

    err = get_template(templ, template);
    if (err)
        return err;

    tmp = strdup(templ);
    if (tmp == NULL)
        return (errno == 0) ? -ENOMEM : -errno;

    dfd = open(dirname(tmp), DIR_OPEN_FLAGS);
    err = -errno;
    free(tmp);
    if (dfd == -1)
        return err;

    tmp = basename_safe(templ);

    if (mkdirat(dfd, tmp, ACC_MODE_ACCESS_PERMS) == -1)
        goto err;

    fd = openat(dfd, tmp, DIR_OPEN_FLAGS);
    if (fd == -1)
        goto err;

    close(dfd);

    err = (fchdir(fd) == -1) ? -errno : 0;

    close(fd);

    return err;

err:
    err = -errno;
    close(dfd);
    return err;
}

/* vi: set expandtab sw=4 ts=4: */
