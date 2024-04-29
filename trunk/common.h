/*
 * common.h
 */

#ifndef _COMMON_H
#define _COMMON_H

#include "config.h"

#include <stdio.h>

#define EXPORTED __attribute__((__visibility__("default")))

#define stderrchr(c) fputc(c, stderr)
#define stderrmsg(msg) fputs(msg, stderr)
#define stderrmsgf(...) fprintf(stderr, __VA_ARGS__)

#define infochr stderrchr
#define infomsg stderrmsg
#define infomsgf stderrmsgf

#define errmsg stderrmsg
#define errmsgf stderrmsgf

#ifdef HAVE_ERROR
#include <error.h>
#elif defined(HAVE_ERRC) && defined(HAVE_WARNC)
#include <err.h>
#define error(eval, code, ...) \
    do { \
        if ((eval) == 0) \
            warnc(code, __VA_ARGS__); \
        else \
            errc(eval, code, __VA_ARGS__); \
    } while (0)
#else
#include <stdio.h>
#include <stdlib.h>
#define error(eval, code, ...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, ": error code %d\n", code); \
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

static _Thread_local int asserttmp;

#define ERRNO (asserttmp = errno, assert(asserttmp > 0), asserttmp)
#define MINUS_ERRNO (asserttmp = -errno, assert(asserttmp < 0), asserttmp)
#endif

#define _STR(x) #x
#define STR(x) _STR(x)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif

/* vi: set expandtab sw=4 ts=4: */
