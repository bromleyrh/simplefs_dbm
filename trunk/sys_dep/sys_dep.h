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

int blk_get_size(int fd, uint64_t *count);

#endif

/* vi: set expandtab sw=4 ts=4: */
