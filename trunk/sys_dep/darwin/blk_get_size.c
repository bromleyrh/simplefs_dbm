/*
 * blk_get_size.c
 */

#include "sys_dep.h"

#include <stdint.h>

#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/types.h>

int
blk_get_size(int fd, uint64_t *count)
{
    uint64_t ret;
    uint64_t size;

    if (ioctl(fd, DKIOCGETBLOCKCOUNT, &ret) == -1
        || ioctl(fd, DKIOCGETBLOCKSIZE, &size) == -1)
        return -1;

    *count = ret * size;
    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
