/*
 * back_end.h
 */

#ifndef _BACK_END_H
#define _BACK_END_H

#include <sys/types.h>

struct back_end;

struct db_args {
    const char  *db_pathname;
    mode_t      db_mode;
};

int back_end_create(struct back_end **be, int root_id, void *args);

int back_end_open(struct back_end **be, void *args);

int back_end_close(struct back_end *be);

#endif

/* vi: set expandtab sw=4 ts=4: */
