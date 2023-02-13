/*
 * simplefs.h
 */

#ifndef _SIMPLEFS_H
#define _SIMPLEFS_H

struct mount_data {
    char        *creds;
    int         wd;
    const char  *db_pathname;
    const char  *mountpoint;
    unsigned    ro;
    unsigned    lkw;
    unsigned    fmtconv;
    unsigned    debug;
    unsigned    unmount;
    int         pipefd;
    void        *priv;
};

#endif

/* vi: set expandtab sw=4 ts=4: */
