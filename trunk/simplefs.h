/*
 * simplefs.h
 */

#ifndef _SIMPLEFS_H
#define _SIMPLEFS_H

struct mount_data {
    const char  *db_pathname;
    const char  *mountpoint;
    unsigned    ro;
    unsigned    fmtconv;
    void        *priv;
};

void simplefs_exit(void);

#endif

/* vi: set expandtab sw=4 ts=4: */
