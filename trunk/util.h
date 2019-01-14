/*
 * util.h
 */

#ifndef _UTIL_H
#define _UTIL_H

#include <stddef.h>

void *do_malloc(size_t size);
void *do_calloc(size_t nmemb, size_t size);
void *do_realloc(void *ptr, size_t size);

#endif

/* vi: set expandtab sw=4 ts=4: */
