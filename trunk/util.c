/*
 * util.c
 */

#include "config.h"

#include "util.h"

#define ASSERT_MACROS
#include "common.h"
#undef ASSERT_MACROS

#include <avl_tree.h>
#include <forensics.h>
#include <io_ext.h>
#include <malloc_ext.h>
#include <sort.h>
#include <strings_ext.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#if defined(__GLIBC__) || defined(__APPLE__)
#define HAVE_BACKTRACE
#endif

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#endif

#ifdef __linux__
#define HAVE_ADDR2LINE
#endif

enum {
    IO_RD = 1,
    IO_WR = 2
};

typedef ssize_t (*io_rd_fn_t)(int, void *, size_t, off_t,
                              const struct interrupt_data *);
typedef ssize_t (*io_wr_fn_t)(int, const void *, size_t, off_t,
                              const struct interrupt_data *);

struct io_buffers {
    const void  *in_p;
    size_t      in_nb;
    io_wr_fn_t  wr;
    void        *out_p;
    size_t      out_nb;
    io_rd_fn_t  rd;
    unsigned    mask;
};

struct err_info {
    int     errdes;
    int     errcode;
    void    *data;
};

struct err_info_walk_ctx {
    int     (*cb)(int, void *, void *);
    void    *ctx;
};

static _Thread_local struct err_data {
    int             curr_errdes;
    struct avl_tree *err_info;
} err_data;

#define ASSURE_ERRNO_SET(ret, expr) \
    do { \
        errno = 0; \
        (ret) = (expr); \
        if ((ret) == NULL && errno == 0) \
            errno = ENOMEM; \
    } while (0)

#ifndef NDEBUG
static int strlen_cmp(const void *, const void *, void *);

#endif
#ifdef HAVE_ADDR2LINE
static int close_pipe(int [2]);

#endif
static int interrupt_recv(const struct interrupt_data *);

static size_t do_io(int, const struct io_buffers *, off_t, size_t,
                    const struct interrupt_data *);

static ssize_t read_fn(int, void *, size_t, off_t,
                       const struct interrupt_data *);
static ssize_t write_fn(int, const void *, size_t, off_t,
                        const struct interrupt_data *);

static int get_locale(locale_t *);

static int strerror_lr(int, char *, size_t, locale_t);

static int err_info_cmp(const void *, const void *, void *);
static int err_info_walk_cb(const void *, void *);

static int init_err_data(struct err_data *);

#ifdef HAVE_ADDR2LINE
static int xlat_addr2line_bt(FILE *, const char *, const char *, unsigned);

#endif

#ifndef NDEBUG
static int
strlen_cmp(const void *e1, const void *e2, void *ctx)
{
    size_t len1, len2;
    ssize_t *maxlen = ctx;

    len1 = strlen(*(char *const *)e1);
    if (*maxlen == -1)
        len2 = strlen(*(char *const *)e2);
    else
        len2 = *maxlen;

    if (len1 > len2) {
        *maxlen = len1;
        return 1;
    }
    if (*maxlen == -1)
        *maxlen = len2;

    return len1 < len2 ? -1 : 0;
}

#endif

#ifdef HAVE_ADDR2LINE
static int
close_pipe(int pfd[2])
{
    int err;

    err = close(pfd[0]) == -1 ? MINUS_ERRNO : 0;
    return close(pfd[1]) == -1 ? MINUS_ERRNO : err;
}

#endif

static int
interrupt_recv(const struct interrupt_data *intdata)
{
    if (intdata != NULL && intdata->interrupted != NULL
        && (*intdata->interrupted)()) {
        errno = EINTR;
        return 1;
    }

    return 0;
}

static size_t
do_io(int fd, const struct io_buffers *bufs, off_t offset, size_t maxlen,
      const struct interrupt_data *intdata)
{
    size_t len;
    size_t num_processed;
    ssize_t ret;

    if (bufs->mask == (IO_RD | IO_WR)) {
        errno = ENOSYS;
        return 0;
    }

    len = bufs->mask == IO_RD ? bufs->out_nb : bufs->in_nb;
    if (maxlen == 0)
        maxlen = ~(size_t)0;

    for (num_processed = 0; num_processed < len; num_processed += ret) {
        size_t length = MIN(len - num_processed, maxlen);

        if (interrupt_recv(intdata))
            break;

        errno = 0;
        if (bufs->mask == IO_RD) {
            ret = (*bufs->rd)(fd, (char *)bufs->out_p + num_processed, length,
                              offset + num_processed, intdata);
        } else {
            ret = (*bufs->wr)(fd, (const char *)bufs->in_p + num_processed,
                              length, offset + num_processed, intdata);
        }
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
write_fn(int fd, const void *buf, size_t len, off_t offset,
         const struct interrupt_data *intdata)
{
    (void)offset;
    (void)intdata;

    return write(fd, buf, len);
}

static int
get_locale(locale_t *loc)
{
    locale_t ret;

    ret = uselocale((locale_t)0);
    if (ret == (locale_t)0)
        return ERRNO;

    ret = duplocale(ret);
    if (ret == (locale_t)0)
        return ERRNO;

    *loc = ret;
    return 0;
}

static int
strerror_lr(int errnum, char *strerrbuf, size_t buflen, locale_t loc)
{
#ifdef HAVE_STRERROR_L
    char *ret;
    int err, old_errno;

    old_errno = errno;
    errno = 0;
    ret = strerror_l(errnum, loc);
    err = errno;
    errno = old_errno;
    if (ret == NULL)
        return err ? err : EIO;

    return _strlcpy(strerrbuf, ret, buflen) < buflen ? err : ERANGE;
#else
    (void)loc;

    return strerror_r(errnum, strerrbuf, buflen);
#endif
}

static int
err_info_cmp(const void *k1, const void *k2, void *ctx)
{
    const struct err_info *info1 = k1;
    const struct err_info *info2 = k2;

    (void)ctx;

    return (info1->errdes > info2->errdes) - (info1->errdes < info2->errdes);
}

static int
err_info_walk_cb(const void *keyval, void *ctx)
{
    const struct err_info *info = keyval;
    const struct err_info_walk_ctx *ectx = ctx;

    return (*ectx->cb)(info->errcode, info->data, ectx->ctx);
}

static int
init_err_data(struct err_data *err_data)
{
    int err;

    err = avl_tree_new(&err_data->err_info, sizeof(struct err_info),
                       &err_info_cmp, 0, NULL, NULL, NULL);
    if (!err)
        err_data->curr_errdes = ERRDES_MIN;

    return err;
}

#ifdef HAVE_ADDR2LINE
static int
xlat_addr2line_bt(FILE *f, const char *fmt, const char *path, unsigned reloff)
{
    char *str1, *str2;
    FILE *inf, *outf;
    int err, res;
    int inpfd[2], outpfd[2];
    size_t len;
    pid_t pid;

    if (pipe(inpfd) == -1)
        return MINUS_ERRNO;
    if (pipe(outpfd) == -1) {
        err = MINUS_ERRNO;
        close_pipe(inpfd);
        return err;
    }

    inf = outf = NULL;

    pid = fork();
    if (pid == 0) {
        close(inpfd[1]);
        close(outpfd[0]);

        if (dup2(inpfd[0], STDIN_FILENO) != -1
            && dup2(outpfd[1], STDOUT_FILENO) != -1)
            execlp("addr2line", "addr2line", "-e", path, "-f", "-s", NULL);

        close(inpfd[0]);
        close(outpfd[1]);
        _exit(EXIT_FAILURE);
    }
    close(inpfd[0]);
    close(outpfd[1]);
    if (pid == -1)
        goto err3;

    inf = fdopen(inpfd[1], "w");
    if (inf == NULL)
        goto err3;
    if (setvbuf(inf, NULL, _IOLBF, 0) == EOF) {
        err = -ENOMEM;
        goto err2;
    }
    outf = fdopen(outpfd[0], "r");
    if (outf == NULL)
        goto err3;

    if (fprintf(inf, "%x\n", reloff) < 0) {
        err = -EIO;
        goto err2;
    }

    str1 = NULL;
    len = 0;
    if (getline(&str1, &len, outf) == -1) {
        err = errno == 0 ? -EIO : MINUS_ERRNO;
        goto err2;
    }
    len = strlen(str1);
    if (len > 0) {
        --len;
        if (str1[len] == '\n')
            str1[len] = '\0';
    }

    str2 = NULL;
    len = 0;
    if (getline(&str2, &len, outf) == -1) {
        err = errno == 0 ? -EIO : MINUS_ERRNO;
        free(str1);
        goto err2;
    }
    len = strlen(str2);
    if (len > 1) {
        --len;
        if (str2[len] == '\n')
            str2[len] = '\0';
    }

    res = fprintf(f, fmt, str1, str2);
    free(str1);
    free(str2);
    if (res < 0) {
        err = -EIO;
        goto err2;
    }

    fclose(outf);
    if (fclose(inf) == EOF) {
        err = MINUS_ERRNO;
        goto err1;
    }

    return waitpid(pid, &res, 0) == -1
           || !WIFEXITED(res) || WEXITSTATUS(res) != 0
           ? MINUS_ERRNO : 0;

err3:
    err = MINUS_ERRNO;
err2:
    if (outf == NULL)
        close(outpfd[0]);
    else
        fclose(outf);
    if (inf == NULL)
        close(inpfd[1]);
    else
        fclose(inf);
err1:
    if (pid != -1)
        waitpid(pid, &res, 0);
    return err;
}

#endif

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
do_allocarray(size_t nmemb, size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, allocarray(nmemb, size));
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

void *
do_reallocarray(void *ptr, size_t nmemb, size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, reallocarray(ptr, nmemb, size));
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
    struct io_buffers bufs = {
        .out_p  = buf,
        .out_nb = len,
        .rd     = &read_fn,
        .mask   = IO_RD
    };

    return do_io(fd, &bufs, -1, maxread, NULL);
}

size_t
do_write(int fd, const void *buf, size_t len, size_t maxwrite)
{
    struct io_buffers bufs = {
        .in_p   = buf,
        .in_nb  = len,
        .wr     = &write_fn,
        .mask   = IO_WR
    };

    return do_io(fd, &bufs, -1, maxwrite, NULL);
}

size_t
do_ppread(int fd, void *buf, size_t len, off_t offset, size_t maxread,
          const struct interrupt_data *intdata)
{
    struct io_buffers bufs = {
        .out_p  = buf,
        .out_nb = len,
        .rd     = &ppread,
        .mask   = IO_RD
    };

    return do_io(fd, &bufs, offset, maxread, intdata);
}

size_t
do_ppwrite(int fd, const void *buf, size_t len, off_t offset, size_t maxwrite,
           const struct interrupt_data *intdata)
{
    struct io_buffers bufs = {
        .in_p   = buf,
        .in_nb  = len,
        .wr     = &ppwrite,
        .mask   = IO_WR
    };

    return do_io(fd, &bufs, offset, maxwrite, intdata);
}

int
do_pfsync_dev(int fd, const struct interrupt_data *intdata)
{
    return interrupt_recv(intdata) ? -1 : pfsync_dev(fd, intdata);
}

int
do_pfdatasync_dev(int fd, const struct interrupt_data *intdata)
{
    return interrupt_recv(intdata) ? -1 : pfdatasync_dev(fd, intdata);
}

int
gettime(clockid_t clk_id, struct timespec *tm)
{
#ifdef HAVE_CLOCK_GETTIME
    return clock_gettime(clk_id, tm) == -1 ? MINUS_ERRNO : 0;
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

int
strerror_rp(int errnum, char *strerrbuf, size_t buflen)
{
    int err;
    locale_t loc;

    err = get_locale(&loc);
    if (!err) {
        err = strerror_lr(errnum, strerrbuf, buflen, loc);
        freelocale(loc);
    }

    return err;
}

char *
strperror_r(int errnum, char *strerrbuf, size_t buflen)
{
#ifdef HAVE_STRERROR_L
    char *ret;
    int err;
    locale_t loc;

    static _Thread_local char buf[32];

    if (get_locale(&loc) != 0) {
        snprintf(buf, sizeof(buf), "%d", errnum);
        return buf;
    }

    err = strerror_lr(errnum, strerrbuf, buflen, loc);
    ret = err ? strerror_l(errnum, loc) : strerrbuf;
    freelocale(loc);
    return ret;
#else
    const char *fmt = "%d";
    int err;
    locale_t loc;

    static _Thread_local char buf[32];

    err = get_locale(&loc);
    if (err)
        goto err;

    err = strerror_lr(errnum, strerrbuf, buflen, loc);
    freelocale(loc);
    if (err) {
        if (err == EINVAL)
            fmt = "Unknown error %d";
        goto err;
    }

    return strerrbuf;

err:
    snprintf(buf, sizeof(buf), fmt, errnum);
    return buf;
#endif
}

int
err_tag(int errcode, void *data)
{
    int errdes;
    struct err_info info;

    if (errcode >= ERRDES_MIN)
        errcode = -EIO;

    if (err_data.err_info == NULL) {
        if (init_err_data(&err_data) != 0)
            goto err;
    } else if (err_data.curr_errdes == 0) /* overflow */
        goto err;

    errdes = err_data.curr_errdes;

    info.errdes = errdes;
    info.errcode = errcode;
    info.data = data;

    if (avl_tree_insert(err_data.err_info, &info) != 0)
        goto err;

    err_data.curr_errdes = errdes == INT_MAX ? 0 : errdes + 1;

    return errdes;

err:
    return errcode;
}

void *
err_get(int errdes, int *errcode)
{
    struct err_info info;

    if (err_data.err_info == NULL)
        goto err;

    info.errdes = errdes;

    if (avl_tree_search(err_data.err_info, &info, &info) != 1)
        goto err;

    *errcode = info.errcode;
    return info.data;

err:
    *errcode = errdes;
    return NULL;
}

int
err_get_code(int errdes)
{
    int ret;

    err_get(errdes, &ret);

    return ret;
}

int
err_clear(int errdes)
{
    int err;
    struct err_info info;

    if (err_data.err_info == NULL)
        return -ENOENT;

    info.errdes = errdes;

    err = avl_tree_delete(err_data.err_info, &info);
    if (!err && errdes == err_data.curr_errdes - 1)
        err_data.curr_errdes = errdes;

    return err;
}

int
err_foreach(int (*cb)(int, void *, void *), void *ctx)
{
    avl_tree_walk_ctx_t wctx = NULL;
    struct err_info_walk_ctx ectx;

    ectx.cb = cb;
    ectx.ctx = ctx;

    return avl_tree_walk(err_data.err_info, NULL, &err_info_walk_cb, &ectx,
                         &wctx);
}

int
_err_tag_bt(int errcode, const char *file, int line)
{
    struct err_info_bt *info;
    int res;
    void *array[32];

    (void)array;

    info = malloc(sizeof(*info));
    if (info == NULL)
        return errcode;

    info->file = file;
    info->line = line;
    info->bt = NULL;
    info->len = 0;

#ifdef HAVE_BACKTRACE
    res = backtrace(array, ARRAY_SIZE(array));
    if (res > 0) {
        info->bt = backtrace_symbols(array, res);
        info->len = res;
    }

#endif
    res = err_tag(errcode, info);
    if (res >= ERRDES_MIN)
        info->errdes = res;
    else
        free(info);

    return res;
}

struct err_info_bt *
err_get_bt(int *err)
{
    return err_get(*err, err);
}

int
err_info_free(struct err_info_bt *info, int freeall)
{
    int err;

    err = err_clear(info->errdes);
    if (!err) {
        if (freeall)
            free(info->bt);
        free(info);
    }

    return err;
}

int
err_print(FILE *f, int *err)
{
    char strerrbuf[256];
    int i;
    int ret;
    struct err_info_bt *info;

    info = err_get_bt(err);
    if (info == NULL)
        return 0;

    ret = -EIO;

    if (fprintf(f, "Error at %s:%d\n", info->file, info->line) < 0)
        goto end;

    for (i = 1; i < info->len; i++) {
#ifdef HAVE_ADDR2LINE
        char buf[PATH_MAX];
        unsigned off, reloff;

        if (sscanf(info->bt[i], "%" STR(PATH_MAX) "[^(](+0x%x) [0x%x]",
                   buf, &reloff, &off)
            == 3
            || sscanf(info->bt[i], "%" STR(PATH_MAX) "[^(]() [0x%x]",
                      buf, &reloff)
               == 2) {
            if (xlat_addr2line_bt(f, "%32s(), %s\n", buf, reloff) != 0)
                goto end;
            continue;
        }

        if (sscanf(info->bt[i], "%*[^(](%64[^+]+0x%x) [0x%x]", buf, &reloff,
                   &off)
            == 3) {
            if (fprintf(f, "%32s(), +0x%04x byte%s\n", buf, PL(reloff)) < 0)
                goto end;
            continue;
        }

#endif
        if (fprintf(f, "%s\n", info->bt[i]) < 0)
            goto end;
    }

    if (fprintf(f, "%s\n", strperror_r(-*err, strerrbuf, sizeof(strerrbuf)))
        >= 0)
        ret = 0;

end:
    err_info_free(info, 1);
    return ret;
}

/* vi: set expandtab sw=4 ts=4: */
