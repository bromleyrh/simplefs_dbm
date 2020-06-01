/*
 * test_util_shell.c
 */

#include "test_util_shell.h"
#include "util_test_common.h"

#include <stdio.h>

int
cmd_send_cb(const char *cmd, void *ctx)
{
    FILE *testlog = *testlogp;

    (void)ctx;

    fprintf(testlog, "%s\n", cmd);
    fflush(testlog);

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
