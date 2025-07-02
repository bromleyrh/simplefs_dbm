/*
 * blk_get_size.c
 */

#include "sys_dep.h"

#include <errno.h>
#include <stdint.h>

int
blk_get_size(int fd, uint64_t *count)
{
    (void)fd;
    (void)count;

    errno = ENOTSUP;
    return -1;
}

/* vi: set expandtab sw=4 ts=4: */
