/*
 * simplefs.h
 */

#ifndef _SIMPLEFS_H
#define _SIMPLEFS_H

struct mount_data {
    char        *creds;
    int         wd;
    char        *db_pathname;
    char        *mountpoint;
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
