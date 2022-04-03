/*
 * lib_test_log.c
 */

#include "util_test_common.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <io_ext.h>
#include <strings_ext.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>

static char checklogname[NAME_MAX+1];
static char testlogname[NAME_MAX+1];

EXPORTED const char *checklogprefix;
EXPORTED const char *logprefix;
EXPORTED FILE **testlogp;

FILE *
open_log_file(int checklog)
{
    if (checklog) {
        FILE *f;

        if (checklogname[0] == '\0') {
            snprintf(checklogname, NAME_MAX + 1, "%s%d.txt", checklogprefix,
                     getpid());
        }

        f = fopen_flags(checklogname, "w", FOPEN_CLOEXEC);
        if (f == NULL)
            error(0, errno, "Couldn't open verification log file");

        return f;
    }

    if (testlogname[0] == '\0') {
        snprintf(testlogname, NAME_MAX + 1, "%s%d.txt", logprefix,
                 getpid());
    }

    *testlogp = fopen_flags(testlogname, "w", FOPEN_CLOEXEC);
    if (*testlogp == NULL)
        error(0, errno, "Couldn't open command log file");

    return *testlogp;
}

int
close_log_file(FILE *f)
{
    if (f == NULL)
        return *testlogp == NULL ? 0 : fclose(*testlogp);

    return fclose(f);
}

void
show_log_names()
{
    union fmt_arg args;

    if (testlogname[0] != '\0') {
        args.string = testlogname;
        sig_dprintf(STDERR_FILENO, "Log file: %s\n", &args);
    }
    if (checklogname[0] != '\0') {
        args.string = checklogname;
        sig_dprintf(STDERR_FILENO, "Verification log file: %s\n", &args);
    }
}

/* vi: set expandtab sw=4 ts=4: */
