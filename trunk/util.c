/*
 * util.c
 */

#include "util.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

#define ASSURE_ERRNO_SET(ret, expr) \
    do { \
        errno = 0; \
        (ret) = (expr); \
        if (((ret) == NULL) && (errno == 0)) \
            errno = ENOMEM; \
    } while (0)

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

/* vi: set expandtab sw=4 ts=4: */
