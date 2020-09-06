/*
 * umount.simplefs.c
 */

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#define UMOUNT_MOUNTPOINT_ARGV_IDX 1

#define SIMPLEFS_PATH "simplefs"

int
main(int argc, char **argv)
{
    const char *mountpoint;

    if (argc <= UMOUNT_MOUNTPOINT_ARGV_IDX)
        error(EXIT_FAILURE, 0, "Missing mountpoint parameter");
    mountpoint = argv[UMOUNT_MOUNTPOINT_ARGV_IDX];

    execlp(SIMPLEFS_PATH, SIMPLEFS_PATH, "-u", mountpoint, NULL);

    error(0, errno, "Error executing");
    error(0, 0, "Try running \"simplefs -u %s\"", mountpoint);
    error(0, 0, "or \"fusermount -u %s\"", mountpoint);

    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
