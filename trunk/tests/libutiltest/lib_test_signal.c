/*
 * lib_test_signal.c
 */

#include "util_test_common.h"

#include <forensics.h>
#include <io_ext.h>

#include <signal.h>
#include <stddef.h>
#include <stdio.h>

void
test_segv_handler(FILE *log)
{
    struct sigaction sa;

    if (log != NULL)
        sig_fflush_unlocked(log);
    show_log_names();

    sa.sa_sigaction = sigaction_segv_diag;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    raise(SIGSEGV);
}

/* vi: set expandtab sw=4 ts=4: */
