/*
 * test_util_cont_shell.c
 */

#include "test_util_cont.h"
#include "test_util_cont_shell.h"
#include "test_util_shell.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <test_util.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#define CMD_ARGS(cmdctx, cmdargs) \
    struct cont_cmd_args *args = (struct cont_cmd_args *)cmdargs; \
    struct cmd_ctx *ctx = (struct cmd_ctx *)cmdctx; \
    struct cont_cmd_data *cmddata = (struct cont_cmd_data *)(ctx->cmddata)

static int shell_check_assertion(void *, int (*)(struct cont_ctx *, int, int *),
                                 int);

static int
shell_check_assertion(void *ctx,
                      int (*search_container)(struct cont_ctx *, int, int *),
                      int assert_key)
{
    int res, ret;

    ret = (*search_container)(ctx, assert_key, &res);
    if (ret == 1)
        fprintf(stderr, "Assertion succeeded: key %d found\n", assert_key);
    else if (ret == 0) {
        fprintf(stderr, "Assertion failed: key %d not found\n", assert_key);
        while (!quit)
            pause();
        quit = 0;
    } else {
        error(0, -ret, "Error looking up in container");
        return ret;
    }

    return 0;
}

int
ins_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);

    return cont_insert((struct cont_ctx *)(cmddata->ctx), args->key, NULL, 1,
                       cmddata->verbose, 1);
}

int
del_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);

    return cont_delete((struct cont_ctx *)(cmddata->ctx), args->key, NULL, 1,
                       cmddata->verbose, 1);
}

int
find_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);

    return cont_find((struct cont_ctx *)(cmddata->ctx), args->key, NULL,
                     cmddata->verbose, 1);
}

int
select_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);

    return cont_select((struct cont_ctx *)(cmddata->ctx), args->key, NULL,
                       cmddata->verbose, 1);
}

int
rank_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);

    return cont_get_index((struct cont_ctx *)(cmddata->ctx), args->key, NULL,
                          cmddata->verbose, 1);
}

int
assert_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);

    cmddata->assert_key = args->key;
    return 0;
}

int
dump_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);
    FILE *f;
    int ret;

    (void)args;

    f = fopen("dump.txt", "w");
    if (f == NULL) {
        ret = -errno;
        error(0, errno, "Couldn't open dump file");
        return ret;
    }

    ret = (*(cmddata->dump_container))(f, cmddata->ctx);
    if (ret != 0)
        error(0, -ret, "Error dumping container");
    fclose(f);

    return ret;
}

int
stat_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);

    (void)args;

    (*(cmddata->print_stats))(stderr, cmddata->ctx, 0);
    return 0;
}

int
walk_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);

    (void)args;

    return (*(cmddata->walk_container))(cmddata->ctx);
}

int
next_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);
    int err;

    (void)args;

    if (cmddata->iter == NULL)
        err = (*(cmddata->alloc_iter))(&cmddata->iter, cmddata->ctx);
    else
        err = (*(cmddata->increment_iter))(cmddata->iter);
    if (err)
        error(0, -err, "Error");
    else {
        int res;

        err = (*(cmddata->access_iter))(cmddata->iter, &res);
        if (err)
            error(0, -err, "Error");
        else
            printf("%d\n", res);
    }

    return 0;
}

int
prev_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);
    int err;

    (void)args;

    if (cmddata->iter == NULL)
        err = (*(cmddata->alloc_iter))(&cmddata->iter, cmddata->ctx);
    else
        err = (*(cmddata->decrement_iter))(cmddata->iter);
    if (err)
        error(0, -err, "Error");
    else {
        int res;

        err = (*(cmddata->access_iter))(cmddata->iter, &res);
        if (err)
            error(0, -err, "Error");
        else
            printf("%d\n", res);
    }

    return 0;
}

int
search_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);
    int res;

    if (cmddata->iter == NULL) {
        res = (*(cmddata->alloc_iter))(&cmddata->iter, cmddata->ctx);
        if (res != 0) {
            error(0, -res, "Error");
            return 0;
        }
    }

    res = (*(cmddata->seek_iter))(cmddata->iter, args->key);
    if (res != 1) {
        if (res == 0)
            error(0, 0, "Not found");
        else
            error(0, -res, "Error");
    }

    return 0;
}

int
isearch_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);
    int res;

    if (cmddata->iter == NULL) {
        res = (*(cmddata->alloc_iter))(&cmddata->iter, cmddata->ctx);
        if (res != 0) {
            error(0, -res, "Error");
            return 0;
        }
    }

    res = (*(cmddata->seek_iter_idx))(cmddata->iter, args->key);
    if (res != 1) {
        if (res == 0)
            error(0, 0, "Not found");
        else
            error(0, -res, "Error");
    }

    return 0;
}

int
reset_cmd(void *cmdctx, void *cmdargs)
{
    CMD_ARGS(cmdctx, cmdargs);
    int err;

    (void)args;

    if (cmddata->iter != NULL) {
        err = (*(cmddata->free_iter))(cmddata->iter);
        if (err) {
            error(0, -err, "Error freeing iterator");
            return 0;
        }
        cmddata->iter = NULL;
    }

    return 0;
}

int
cmd_listen_cb_cont(const char *cmd, void *ctx)
{
    struct cont_cmd_data *cmddata = ((struct cmd_ctx *)ctx)->cmddata;

    (void)cmd;

    if ((cmddata->assert_key >= 0)
        && (shell_check_assertion(cmddata->ctx, cmddata->search_container,
                                  cmddata->assert_key) == -1))
        return -1;

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
