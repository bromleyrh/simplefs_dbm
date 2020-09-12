/*
 * util.c
 */

#include "config.h"

#include "common.h"
#include "util.h"

#include <forensics.h>
#include <io_ext.h>
#include <sort.h>

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

typedef ssize_t (*io_fn_t)(int, void *, size_t, off_t,
                           const struct interrupt_data *);

#define ASSURE_ERRNO_SET(ret, expr) \
    do { \
        errno = 0; \
        (ret) = (expr); \
        if (((ret) == NULL) && (errno == 0)) \
            errno = ENOMEM; \
    } while (0)

#ifndef NDEBUG
static int strlen_cmp(const void *, const void *, void *);

#endif
static int interrupt_recv(const struct interrupt_data *);

static size_t do_io(io_fn_t, int, void *, size_t, off_t, size_t,
                    const struct interrupt_data *);

static ssize_t read_fn(int, void *, size_t, off_t,
                       const struct interrupt_data *);
static ssize_t write_fn(int, void *, size_t, off_t,
                        const struct interrupt_data *);

#ifndef NDEBUG
static int
strlen_cmp(const void *e1, const void *e2, void *ctx)
{
    size_t len1, len2;
    ssize_t *maxlen = (ssize_t *)ctx;

    len1 = strlen(*(const char **)e1);
    if (*maxlen == -1)
        len2 = strlen(*(const char **)e2);
    else
        len2 = *maxlen;

    if (len1 > len2) {
        *maxlen = len1;
        return 1;
    }
    if (*maxlen == -1)
        *maxlen = len2;

    return (len1 < len2) ? -1 : 0;
}

#endif
static int
interrupt_recv(const struct interrupt_data *intdata)
{
    if ((intdata != NULL) && (intdata->interrupted != NULL)
        && (*(intdata->interrupted))()) {
        errno = EINTR;
        return 1;
    }

    return 0;
}

static size_t
do_io(io_fn_t fn, int fd, void *buf, size_t len, off_t offset, size_t maxlen,
      const struct interrupt_data *intdata)
{
    size_t num_processed;
    ssize_t ret;

    if (maxlen == 0)
        maxlen = ~((size_t)0);

    for (num_processed = 0; num_processed < len; num_processed += ret) {
        size_t length = MIN(len - num_processed, maxlen);

        if (interrupt_recv(intdata))
            break;

        errno = 0;
        ret = (*fn)(fd, (char *)buf + num_processed, length,
                    offset + num_processed, intdata);
        if (ret <= 0)
            break;
    }

    return num_processed;
}

static ssize_t
read_fn(int fd, void *buf, size_t len, off_t offset,
        const struct interrupt_data *intdata)
{
    (void)offset;
    (void)intdata;

    return read(fd, buf, len);
}

static ssize_t
write_fn(int fd, void *buf, size_t len, off_t offset,
         const struct interrupt_data *intdata)
{
    (void)offset;
    (void)intdata;

    return write(fd, buf, len);
}

void
abort_msg(const char *fmt, ...)
{
    if (fmt != NULL) {
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }

    abort();
}

void
write_backtrace(FILE *f, int start_frame)
{
#ifdef NDEBUG
    (void)f;
    (void)start_frame;

    return;
#else
    char **bt;
    int n;

    bt = get_backtrace(&n);
    if (bt != NULL) {
        int i;
        ssize_t maxlen;

        maxlen = -1;
        max(bt, n, sizeof(*bt), &strlen_cmp, &maxlen);

        fputs("Call stack:\n", f);
        for (i = 1 + start_frame; i < n; i++)
            fprintf(f, "%*s()\n", (int)maxlen, bt[i]);

        free_backtrace(bt);
    }
#endif
}

void *
do_malloc(size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, malloc(size));
    return ret;
}

void *
do_calloc(size_t nmemb, size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, calloc(nmemb, size));
    return ret;
}

void *
do_realloc(void *ptr, size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, realloc(ptr, size));
    return ret;
}

/*
 * Average number of loop iterations for log_2_pow2(), assuming a uniform
 * frequency of inputs constrained to any power of 2
 *
 * Linear search algorithm
 * =======================
 *
 * avg_iterations = sum(1, number_of_bits) / number_of_bits
 *                = 32.5
 *
 * Binary search algorithm
 * =======================
 *
 * 4-bit case:
 * -----------
 *
 * Binary search path lengths:
 * 1     ival = 2, res = 2
 * 2 2   ival = 1, res = 1, 3
 *     0 (input = 1)
 *
 * avg_iterations = (1 + 2 + 2) / 4 = 1.25
 *
 * 64-bit case:
 * ------------
 *
 * Binary search path lengths:
 * 1 *  1 ival = 32
 * 2 *  2 ival = 16
 * 3 *  4 ival =  8
 * 4 *  8 ival =  4
 * 5 * 16 ival =  2
 * 6 * 32 ival =  1
 * 0      (input = 1)
 *
 * avg_iterations =
 * (1 + 2 + 4 + 8 + 16 + 32 = (64 - 1) - (1 - 1)
 *      2 + 4 + 8 + 16 + 32 = (64 - 1) - (2 - 1)
 *          4 + 8 + 16 + 32 = (64 - 1) - (4 - 1)
 *              8 + 16 + 32 = (64 - 1) - (8 - 1)
 *                  16 + 32 = (64 - 1) - (16 - 1)
 *                       32 = (64 - 1) - (32 - 1)
 *  -----------------------   -----------------------------
 *                            6 * (64 - 1) - ((64 - 1) - 6)
 *                            6 * (64 - 1) - (64 - 1) + 6
 *                            (6 - 1) * (64 - 1) + 6
 *                            321
 * ) / 64 = 5.015625
 *
 * avg_iterations = ((n - 1) * (2^n - 1) + n) / (2^n)
 *                  where n = log_2(number_of_bits)
 *                  and number_of_bits is a power of 2
 *                = 5.015625
 */

uint32_t
log_2_pow2(uint64_t n)
{
    uint32_t ival, res;

    assert(n != 0);

    if (n == 1)
        return 0;

    res = ival = 32;
    for (;;) {
        uint64_t tmp = n >> res;

        if (tmp == 1)
            break;

        ival /= 2;
        if (tmp > 1)
            res += ival;
        else
            res -= ival;
    }

    return res;
}

int
is_pipe(int fd)
{
    struct stat s;

    if (fstat(fd, &s) == -1)
        return MINUS_ERRNO;

    return S_ISFIFO(s.st_mode);
}

size_t
do_read(int fd, void *buf, size_t len, size_t maxread)
{
    return do_io(&read_fn, fd, buf, len, -1, maxread, NULL);
}

size_t
do_write(int fd, const void *buf, size_t len, size_t maxwrite)
{
    return do_io(&write_fn, fd, (void *)buf, len, -1, maxwrite, NULL);
}

size_t
do_ppread(int fd, void *buf, size_t len, off_t offset, size_t maxread,
          const struct interrupt_data *intdata)
{
    return do_io(&ppread, fd, buf, len, offset, maxread, intdata);
}

size_t
do_ppwrite(int fd, const void *buf, size_t len, off_t offset, size_t maxwrite,
           const struct interrupt_data *intdata)
{
    return do_io((io_fn_t)&ppwrite, fd, (void *)buf, len, offset, maxwrite,
                 intdata);
}

#ifndef __APPLE__
int
do_pfsync(int fd, const struct interrupt_data *intdata)
{
    return interrupt_recv(intdata) ? -1 : pfsync(fd, intdata);
}

#ifdef HAVE_FDATASYNC
int
do_pfdatasync(int fd, const struct interrupt_data *intdata)
{
    return interrupt_recv(intdata) ? -1 : pfdatasync(fd, intdata);
}

#endif

#endif

int
gettime(clockid_t clk_id, struct timespec *tm)
{
#ifdef HAVE_CLOCK_GETTIME
    return (clock_gettime(clk_id, tm) == -1) ? MINUS_ERRNO : 0;
#else
    struct timeval tv;

    if (clk_id != CLOCK_REALTIME)
        return -ENOTSUP;

    if (gettimeofday(&tv, NULL) == -1)
        return MINUS_ERRNO;

    tm->tv_sec = tv.tv_sec;
    tm->tv_nsec = tv.tv_usec * 1000;
    return 0;
#endif
}

/* vi: set expandtab sw=4 ts=4: */
