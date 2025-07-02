/*
 * util.h
 */

#ifndef _UTIL_H
#define _UTIL_H

#include "config.h"

#include <forensics.h>
#include <io_ext.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define NBWD (sizeof(uint64_t) * CHAR_BIT)

#define SOURCE_LINE_PARAMS const char *func, const char *file, int line
#define SOURCE_LINE __func__, __FILE__, __LINE__

#define _ERR_INJECT(enabled, err_period, funcname, errnum, errret, func, file, \
                    line, set) \
    do { \
        if (enabled) { \
            int err = (set) == 2 || !(random() % (err_period)); \
            if (err) { \
                if ((set) == 1) \
                    (set) = 2; \
                fprintf(stderr, "Injected %s() error in %s() at %s:%d\n", \
                        funcname, func, file, line); \
                write_backtrace(stderr, 0); \
                if ((errnum) != 0) \
                    errno = (errnum); \
                return (errret); \
            } \
        } \
    } while (0)

#define ERR_INJECT(enabled, err_period, errnum, errret, prefixlen, func, file, \
                   line, set) \
    _ERR_INJECT(enabled, err_period, __func__ + prefixlen, errnum, errret, \
                func, file, line, set)

#define ERR_CLEAR(set) \
    do { \
        if ((set) == 2) \
            (set) = 1; \
    } while (0)

#ifndef HAVE_CLOCKID_T
#define clockid_t int
#endif

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 1
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 2
#endif
#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW 3
#endif

void abort_msg(const char *fmt, ...);

void write_backtrace(FILE *f, int start_frame);

void *do_malloc(size_t size);
void *do_allocarray(size_t nmemb, size_t size);
void *do_calloc(size_t nmemb, size_t size);
void *do_realloc(void *ptr, size_t size);
void *do_reallocarray(void *ptr, size_t nmemb, size_t size);

#define oemalloc(ptr) (*(ptr) = do_malloc(sizeof(**(ptr))))
#define oeallocarray(ptr, nmemb) \
    (*(ptr) = do_allocarray(nmemb, sizeof(**(ptr))))
#define oecalloc(ptr, nmemb) (*(ptr) = do_calloc(nmemb, sizeof(**(ptr))))
#define oereallocarray(oldptr, ptr, nmemb) \
    (*(ptr) = do_reallocarray(oldptr, nmemb, sizeof(**(ptr))))

/*
 * log_2_pow2(): calculate the base-2 logarithm of n, which must be a power of 2
 */
uint32_t log_2_pow2(uint64_t n);

int is_pipe(int);

size_t do_read(int, void *, size_t, size_t);
size_t do_write(int, const void *, size_t, size_t);
size_t do_ppread(int, void *, size_t, off_t, size_t,
                 const struct interrupt_data *);
size_t do_ppwrite(int, const void *, size_t, off_t, size_t,
                  const struct interrupt_data *);
int do_pfsync_dev(int, const struct interrupt_data *);
int do_pfdatasync_dev(int, const struct interrupt_data *);

int gettime(clockid_t clk_id, struct timespec *tm);

char *_strptime(const char *s, const char *format, struct tm *tm);

#define INT_OUTPUT(num, e) num, (num) == 1 ? "" : e ? "es" : "s"

#endif

/* vi: set expandtab sw=4 ts=4: */
