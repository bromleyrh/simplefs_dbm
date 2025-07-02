/*
 * sys_dep.h
 */

#ifndef _SYS_DEP_H
#define _SYS_DEP_H

#include "config.h"

#include <stdint.h>

#ifdef HAVE_LINUX_MAGIC_H
#include <linux/magic.h>

#endif
#define FILE_LOCK_SH 1
#define FILE_LOCK_EX 2
#define FILE_LOCK_NB 4
#define FILE_LOCK_UN 8

int blk_get_size(int fd, uint64_t *count);

int fcntl_ofd_setlk(int fd, int operation);

int file_lock(int fd, int operation);

#endif

/* vi: set expandtab sw=4 ts=4: */
