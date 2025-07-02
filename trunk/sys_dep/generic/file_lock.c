/*
 * file_lock.c
 */

#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#include "sys_dep.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <sys/file.h>

int
file_lock(int fd, int operation)
{
    int fl;
    int i;

    static const struct ent {
        int src;
        int dst;
    } flmap[] = {
        {FILE_LOCK_SH, LOCK_SH},
        {FILE_LOCK_EX, LOCK_EX},
        {FILE_LOCK_NB, LOCK_NB},
        {FILE_LOCK_UN, LOCK_UN}
    };

    fl = 0;
    for (i = 0; i < (int)ARRAY_SIZE(flmap); i++) {
        const struct ent *ent = &flmap[i];

        if (operation & ent->src)
            fl |= ent->dst;
    }

    return flock(fd, fl);
}

/* vi: set expandtab sw=4 ts=4: */
