/*
 * blk_get_size.c
 */

#define _FILE_OFFSET_BITS 64

#include "sys_dep.h"

#include <errno.h>
#include <stdint.h>

#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/types.h>

int
blk_get_size(int fd, uint64_t *count)
{
    off_t size;

    if (ioctl(fd, DIOCGMEDIASIZE, &size) == -1)
        return -1;
    if (size < 0) {
        errno = EINVAL;
        return -1;
    }

    *count = size;
    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
