/*
 * fcntl_ofd_setlk.c
 */

#include "config.h"

#ifdef HAVE_FCNTL_F_OFD_LOCKS
#define _GNU_SOURCE
#endif

#include "sys_dep.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int
fcntl_ofd_setlk(int fd, int operation)
{
#ifdef HAVE_FCNTL_F_OFD_LOCKS
    struct flock lk;

    memset(&lk, 0, sizeof(lk));

    if (operation & FILE_LOCK_EX) {
        if (operation & FILE_LOCK_SH)
            goto inval_err;
        lk.l_type = F_WRLCK;
    } else if (operation & FILE_LOCK_SH)
        lk.l_type = F_RDLCK;
    else
        goto inval_err;

    lk.l_whence = SEEK_SET;

    return fcntl(fd, operation & FILE_LOCK_NB ? F_OFD_SETLK : F_OFD_SETLKW,
                 &lk);

inval_err:
    errno = EINVAL;
    return -1;
#else
    (void)fd;
    (void)operation;

    errno = ENOTSUP;
    return -1;
#endif
}

/* vi: set expandtab sw=4 ts=4: */
