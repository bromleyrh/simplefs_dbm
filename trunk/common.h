/*
 * common.h
 */

#ifndef _COMMON_H
#define _COMMON_H

#include "config.h"

#include <stdio.h>

#define EXPORTED __attribute__((__visibility__("default")))

#ifdef HAVE_ERROR
#include <error.h>
#elif defined(HAVE_ERRC) && defined(HAVE_WARNC)
#include <err.h>
#define error(eval, code, format, ...) \
    do { \
        if ((eval) == 0) \
            warnc(code, format, ##__VA_ARGS__); \
        else \
            errc(eval, code, format, ##__VA_ARGS__); \
    } while (0)
#else
#include <stdio.h>
#include <stdlib.h>
#define error(eval, code, format, ...) \
    do { \
        fprintf(stderr, format ": error code %d\n", ##__VA_ARGS__, code); \
        if (eval != 0) \
            exit(eval); \
    } while (0)
#endif

#define ___STATIC_ASSERT(expr, msg) \
    typedef char assertion_##msg[(expr) ? 1 : -1]
#define __STATIC_ASSERT(expr, line) ___STATIC_ASSERT(expr, at_line_##line)
#define _STATIC_ASSERT(expr, line) __STATIC_ASSERT(expr, line)
#define STATIC_ASSERT(expr) _STATIC_ASSERT(expr, __LINE__)

/* for eliminating false negatives from static analysis tools */
#ifndef NO_ASSERT
#include <assert.h>
#include <errno.h>

static __thread int asserttmp;

#define ERRNO (asserttmp = errno, assert(asserttmp > 0), asserttmp)
#define MINUS_ERRNO (asserttmp = -errno, assert(asserttmp < 0), asserttmp)
#endif

#define _STR(x) #x
#define STR(x) _STR(x)

#endif

/* vi: set expandtab sw=4 ts=4: */
