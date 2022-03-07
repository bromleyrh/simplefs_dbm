/*
 * lib_test_common.c
 */

#define _GNU_SOURCE

#include "config.h"

#include "util_test_common.h"

#if !defined(HAVE_POSIX_FALLOCATE) && defined(__APPLE__)
#include "common.h"
#endif

#include <strings_ext.h>

#include <files/acc_ctl.h>
#include <files/util.h>

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef ssize_t (*io_fn_t)(int, void *, size_t, off_t);

#define TEMP_SUFFIX "XXXXXX"
#define TEMP_SUFFIX_CHARS (sizeof(TEMP_SUFFIX) - 1)

#define DIR_OPEN_FLAGS (O_CLOEXEC | O_DIRECTORY | O_RDONLY)

static size_t do_io(io_fn_t, int, void *, size_t, off_t, size_t);

static ssize_t read_fn(int, void *, size_t, off_t);
static ssize_t write_fn(int, void *, size_t, off_t);

static int get_template(char *, const char *);

static size_t
do_io(io_fn_t fn, int fd, void *buf, size_t len, off_t offset, size_t maxlen)
{
    size_t num_processed;
    ssize_t ret;

    if (maxlen == 0)
        maxlen = ~(size_t)0;

    for (num_processed = 0; num_processed < len; num_processed += ret) {
        size_t length = MIN(len - num_processed, maxlen);

        errno = 0;
        ret = (*fn)(fd, (char *)buf + num_processed, length,
                    offset + num_processed);
        if (ret <= 0)
            break;
    }

    return num_processed;
}

static ssize_t
read_fn(int fd, void *buf, size_t len, off_t offset)
{
    (void)offset;

    return read(fd, buf, len);
}

static ssize_t
write_fn(int fd, void *buf, size_t len, off_t offset)
{
    (void)offset;

    return write(fd, buf, len);
}

int
falloc(int fd, off_t offset, off_t len)
{
#if defined(HAVE_POSIX_FALLOCATE)
    return posix_fallocate(fd, offset, len);
#elif defined(__APPLE__)
    off_t curalloc;
    struct stat s;

    if (offset != 0) /* see F_PREALLOCATE comment below */
        return ENOTSUP;
    if (INT64_MAX - offset < len)
        return EFBIG;

    if (fstat(fd, &s) == -1)
        return ERRNO;
    curalloc = s.st_blocks * 512;

    if (len > curalloc) {
        fstore_t stinfo;

        /*
         * F_PREALLOCATE sets the size in bytes of a file's preallocated block
         * pool on APFS (with decreases in size disallowed), while it increases
         * the size of the pool by the given number of bytes on HFS+. It is not
         * known whether space for holes in a file (which must reside in the
         * range [0, s.st_size)) can be allocated from the file's preallocated
         * block pool. It is not possible to reserve preallocated blocks for an
         * arbitrary range of bytes.
         */

        stinfo.fst_flags = F_ALLOCATEALL;
        stinfo.fst_posmode = F_PEOFPOSMODE;
        stinfo.fst_offset = 0;
        /*
         * stinfo.fst_length should be set to the correct preallocated component
         * of len. If the file has no holes, this is len - s.st_size. However,
         * if the file has holes, this component cannot be accurately determined
         * without a scan of the entire file. Thus, len is used below, ensuring
         * that stinfo.fst_length is greater than or equal to the correct
         * preallocated component. This will allocate more than the requested
         * amount of space if the file has no holes.
         */
        stinfo.fst_length = len;

        if (fcntl(fd, F_PREALLOCATE, &stinfo) == -1)
            return ERRNO;
    }

    /* set file size to offset + len, as with posix_fallocate() */
    len += offset;
    if ((s.st_size < len) && (ftruncate(fd, len) == -1))
        return ERRNO;

    return 0;
#else
    (void)fd;
    (void)offset;
    (void)len;

    return ENOSYS;
#endif
}

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

size_t
do_read(int fd, void *buf, size_t len, size_t maxread)
{
    return do_io(&read_fn, fd, buf, len, -1, maxread);
}

size_t
do_write(int fd, const void *buf, size_t len, size_t maxwrite)
{
    return do_io(&write_fn, fd, (void *)buf, len, -1, maxwrite);
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
