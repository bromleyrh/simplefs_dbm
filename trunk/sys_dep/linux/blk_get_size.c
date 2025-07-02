/*
 * blk_get_size.c
 */

#include "config.h"

#include "sys_dep.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#ifdef HAVE_LINUX_FS_H
#include <linux/fs.h>

#include <sys/ioctl.h>

#endif

int
blk_get_size(int fd, uint64_t *count)
{
#ifdef HAVE_LINUX_FS_H
    return ioctl(fd, BLKGETSIZE64, count);
#else
    errno = ENOTSUP;
    return -1;
#endif
}

/* vi: set expandtab sw=4 ts=4: */
