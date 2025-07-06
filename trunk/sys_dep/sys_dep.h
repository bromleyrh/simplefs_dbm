/*
 * sys_dep.h
 */

#ifndef _SYS_DEP_H
#define _SYS_DEP_H

#include "config.h"

#include <stdint.h>
#include <time.h>

#ifdef HAVE_LINUX_MAGIC_H
#include <linux/magic.h>

#endif
struct utim {
    time_t  sec;
    long    nsec;
};

#define FILE_LOCK_SH 1
#define FILE_LOCK_EX 2
#define FILE_LOCK_NB 4
#define FILE_LOCK_UN 8

#define _set_time_nsec(st, which, val) (st_##which##time_nsec(st) = (val))
#define _set_time_nsec_undef(st, which, val)

#define set_time_sec(st, which, val) ((st)->st_##which##time = (val))

#if defined(HAVE_STRUCT_STAT_ST_MTIMENSEC)
#define st_atime_nsec(st) ((st)->st_atimensec)
#define st_mtime_nsec(st) ((st)->st_mtimensec)
#define st_ctime_nsec(st) ((st)->st_ctimensec)
#define set_time_nsec _set_time_nsec
#elif defined(HAVE_STRUCT_STAT_ST_MTIM)
#define st_atime_nsec(st) ((st)->st_atim.tv_nsec)
#define st_mtime_nsec(st) ((st)->st_mtim.tv_nsec)
#define st_ctime_nsec(st) ((st)->st_ctim.tv_nsec)
#define set_time_nsec _set_time_nsec
#else
#define st_atime_nsec(st) 0
#define st_mtime_nsec(st) 0
#define st_ctime_nsec(st) 0
#define set_time_nsec _set_time_nsec_undef
#endif

int blk_get_size(int fd, uint64_t *count);

int fcntl_ofd_setlk(int fd, int operation);

int file_lock(int fd, int operation);

#endif

/* vi: set expandtab sw=4 ts=4: */
