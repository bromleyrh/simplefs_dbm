/*
 * test_util_shell.h
 */

#ifndef _TEST_UTIL_SHELL_H
#define _TEST_UTIL_SHELL_H

#define EXPORTED __attribute__((__visibility__("default")))

#include <test_util.h>

struct cmd_data {
    void *ctx;
};

struct cmd_ctx {
    struct cmdhelp  cmdhelp;
    void            *cmddata;
};

EXPORTED int cmd_send_cb(const char *cmd, void *ctx);

#endif

/* vi: set expandtab sw=4 ts=4: */
