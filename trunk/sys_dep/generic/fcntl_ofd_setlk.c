/*
 * fcntl_ofd_setlk.c
 */

#include "sys_dep.h"

#include <errno.h>

int
fcntl_ofd_setlk(int fd, int operation)
{
    (void)fd;
    (void)operation;

    errno = ENOTSUP;
    return -1;
}

/* vi: set expandtab sw=4 ts=4: */
