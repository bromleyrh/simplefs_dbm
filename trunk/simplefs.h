/*
 * simplefs.h
 */

#ifndef _SIMPLEFS_H
#define _SIMPLEFS_H

struct mount_data {
    const char  *mountpoint;
    unsigned    ro;
    void        *priv;
};

#endif

/* vi: set expandtab sw=4 ts=4: */
