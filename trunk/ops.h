/*
 * ops.h
 */

#ifndef _OPS_H
#define _OPS_H

#include "request.h"

extern struct request_ops request_simplefs_ops;
#define REQUEST_SIMPLEFS ((void *)&request_simplefs_ops)

int mount_status(void);

#endif

/* vi: set expandtab sw=4 ts=4: */
