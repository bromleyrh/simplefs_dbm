/*
 * ops.h
 */

#ifndef _OPS_H
#define _OPS_H

#include <fuse.h>
#include <fuse_lowlevel.h>

extern struct fuse_lowlevel_ops simplefs_ops;

int mount_status(void);

#endif

/* vi: set expandtab sw=4 ts=4: */
