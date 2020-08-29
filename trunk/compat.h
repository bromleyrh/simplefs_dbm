/*
 * compat.h
 */

#ifndef _COMPAT_H
#define _COMPAT_H

#include "back_end.h"

#include <stddef.h>
#include <stdint.h>

int compat_init(struct back_end *be, uint64_t user_ver, uint64_t fs_ver,
                size_t hdrlen, size_t jlen, int ro, int fmtconv);

#endif

/* vi: set expandtab sw=4 ts=4: */
