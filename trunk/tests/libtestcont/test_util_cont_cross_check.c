/*
 * test_util_cont_cross_check.c
 */

#include "test_util_cont.h"
#include "test_util_cont_util.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <bitmap.h>
#include <thread_pool.h>

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

struct search_task_args {
    struct cont_ctx *contctx;
    int             (*fn)(struct cont_ctx *, int, int, int);
    int             key;
    int             use_cont;
    int             use_bitmap;
    int             ret;
};

struct update_task_args {
    struct cont_ctx *contctx;
    int             (*fn)(struct cont_ctx *, int, int, int, int, int, int, int);
    int             key;
    int             replace;
    int             use_cont;
    int             use_bitmap;
    int             nonexistent_allowed;
    int             repeat_allowed;
    int             confirm;
    int             ret;
};

static void search_task(void *);
static void update_task(void *);

static int do_search_task(struct thread_pool *, struct search_task_args *);
static int do_update_task(struct thread_pool *, struct update_task_args *);

static int do_auto_test_delete(struct cont_ctx *, int, int, int, int, int, int,
                               int);

static int auto_test_cross_check_search(struct cont_ctx *, struct cont_ctx *,
                                        struct thread_pool *,
                                        int (*)(struct cont_ctx *, int, int,
                                                int),
                                        int, int, int);
static int auto_test_cross_check_update(struct cont_ctx *, struct cont_ctx *,
                                        struct thread_pool *,
                                        int (*)(struct cont_ctx *, int, int,
                                                int, int, int, int, int),
                                        int, int, int, int, int, int, int,
                                        int *);

static void
search_task(void *args)
{
    struct search_task_args *a = (struct search_task_args *)args;

    a->ret = (*(a->fn))(a->contctx, a->key, a->use_cont, a->use_bitmap);
}

static void
update_task(void *args)
{
    struct update_task_args *a = (struct update_task_args *)args;

    a->ret = (*(a->fn))(a->contctx, a->key, a->replace, a->use_cont,
                        a->use_bitmap, a->nonexistent_allowed,
                        a->repeat_allowed, a->confirm);
}

static int
do_search_task(struct thread_pool *tp, struct search_task_args *args)
{
    thread_pool_task_hdl_t th;

    struct thread_pool_task task = {
        .fn     = &search_task,
        .args   = args,
        .ctx    = NULL
    };

    return thread_pool_add(tp, &th, &task);
}

static int
do_update_task(struct thread_pool *tp, struct update_task_args *args)
{
    thread_pool_task_hdl_t th;

    struct thread_pool_task task = {
        .fn     = &update_task,
        .args   = args,
        .ctx    = NULL
    };

    return thread_pool_add(tp, &th, &task);
}

static int
do_auto_test_delete(struct cont_ctx *contctx, int key, int replace,
                    int use_cont, int use_bitmap, int nonexistent_allowed,
                    int repeat_allowed, int confirm)
{
    (void)replace;
    (void)nonexistent_allowed;

    return auto_test_delete(contctx, key, use_cont, use_bitmap, repeat_allowed,
                            confirm);
}

static int
auto_test_cross_check_search(struct cont_ctx *contctx1,
                             struct cont_ctx *contctx2, struct thread_pool *tp,
                             int (*fn)(struct cont_ctx *, int, int, int),
                             int key, int use_cont, int use_bitmap)
{
    int err;
    thread_pool_task_hdl_t th;

    struct search_task_args args1 = {
        .contctx    = contctx1,
        .fn         = fn,
        .key        = key,
        .use_cont   = use_cont,
        .use_bitmap = use_bitmap,
        .ret        = -EBUSY
    };
    struct search_task_args args2 = {
        .contctx    = contctx2,
        .fn         = fn,
        .key        = key,
        .use_cont   = use_cont,
        .use_bitmap = use_bitmap,
        .ret        = -EBUSY
    };

    if ((err = do_search_task(tp, &args1))
        || (err = do_search_task(tp, &args2)))
        return err;

    if ((err = thread_pool_wait_any(tp, &th, NULL))
        || (err = thread_pool_release(th))
        || (err = thread_pool_wait_any(tp, &th, NULL))
        || (err = thread_pool_release(th)))
        return err;

    return (ERROR_FATAL(args1.ret)
            ? args1.ret
            : (ERROR_FATAL(args2.ret) ? args2.ret : 0));
}

static int
auto_test_cross_check_update(struct cont_ctx *contctx1,
                             struct cont_ctx *contctx2, struct thread_pool *tp,
                             int (*fn)(struct cont_ctx *, int, int, int, int,
                                       int, int, int),
                             int key, int replace, int use_cont, int use_bitmap,
                             int nonexistent_allowed, int repeat_allowed,
                             int confirm, int *force_verify)
{
    int err;
    thread_pool_task_hdl_t th;

    struct update_task_args args1 = {
        .contctx                = contctx1,
        .fn                     = fn,
        .key                    = key,
        .replace                = replace,
        .use_cont               = use_cont,
        .use_bitmap             = use_bitmap,
        .nonexistent_allowed    = nonexistent_allowed,
        .repeat_allowed         = repeat_allowed,
        .confirm                = confirm,
        .ret                    = -EBUSY
    };
    struct update_task_args args2 = {
        .contctx                = contctx2,
        .fn                     = fn,
        .key                    = key,
        .replace                = replace,
        .use_cont               = use_cont,
        .use_bitmap             = use_bitmap,
        .nonexistent_allowed    = nonexistent_allowed,
        .repeat_allowed         = repeat_allowed,
        .confirm                = confirm,
        .ret                    = -EBUSY
    };

    if ((err = do_update_task(tp, &args1))
        || (err = do_update_task(tp, &args2)))
        return err;

    if ((err = thread_pool_wait_any(tp, &th, NULL))
        || (err = thread_pool_release(th))
        || (err = thread_pool_wait_any(tp, &th, NULL))
        || (err = thread_pool_release(th)))
        return err;

    if (ERROR_FATAL(args1.ret))
        return args1.ret;
    if (ERROR_FATAL(args2.ret))
        return args2.ret;

    if (args2.ret == 2)
        *force_verify = 2;
    else if (args1.ret == 2)
        *force_verify = 1;

    return 0;
}

int
cont_test_cross_check(struct cont_ctx *contctx1, struct cont_ctx *contctx2,
                      const struct cont_params *contp, void *ctx, FILE *log)
{
    int (*gen_key_fn)(int, int);
    int ret = 0;
    struct bitmap_data *bmdata;
    struct thread_pool *tp;

    if ((check_search_period(contp) != 0) || (check_max_key(contp) != 0)
        || (contp->test_order_stats
            && ((check_order_stats(contctx1) != 0)
                || (check_order_stats(contctx2) != 0))))
        return -EINVAL;

    if ((set_signal_handler(SIGINT, &int_handler) == -1)
        || (set_signal_handler(SIGTERM, &int_handler) == -1)
        || (set_signal_handler(SIGHUP, &pipe_handler) == -1)
        || (set_signal_handler(SIGPIPE, &pipe_handler) == -1)
        || (set_signal_handler(SIGUSR1, &usr1_handler) == -1)
        || (set_signal_handler(SIGUSR2, &usr2_handler) == -1)) {
        ret = -errno;
        error(0, errno, "Couldn't set signal handler");
        return ret;
    }

    ret = thread_pool_new(&tp, 2, NULL, NULL);
    if (ret != 0)
        goto end1;

    bmdata = (struct bitmap_data *)(contctx1->bmdata);
    gen_key_fn = contp->zero_keys ? &gen_key : &gen_key_no_zero;

    while (!quit && (NUM_OPS(contctx1) < contp->num_ops)) {
        int force_verify = 0;
        int key;
        int delete, search;

        ret = handle_usr_signals(contctx1, contctx2, ctx);
        if (ret != 0)
            break;

        key = (*gen_key_fn)(contp->max_key, 0);

        search = !(random() % contp->search_period);
        if (search) {
            int (*fn)(struct cont_ctx *, int, int, int);

            if (contp->test_walk)
                search = random() % (contp->test_order_stats ? 4 : 2);
            else
                search = 1 + random() % (contp->test_order_stats ? 3 : 1);
            switch (search) {
            case 0:
                fn = &auto_test_walk;
                break;
            case 1:
                fn = &auto_test_search;
                break;
            case 2:
                fn = &auto_test_select;
                break;
            case 3:
                fn = &auto_test_get_index;
                break;
            default:
                ret = -EIO;
                goto end2;
            }
            ret = auto_test_cross_check_search(contctx1, contctx2, tp, fn, key,
                                               1, 1);
            if (ret < 0)
                goto end2;
            if (!(contp->verify_after_search))
                continue;
        } else {
            delete = bitmap_get(bmdata->bitmap, key);
            if (!delete) {
                int replace = contp->test_replace ? random() % 2 : 0;

                VERBOSE_LOG(log, "ins %d\n", key);
                ret = auto_test_cross_check_update(contctx1, contctx2, tp,
                                                   &auto_test_insert, key,
                                                   replace, 1, 1, 1, 0,
                                                   contp->confirm,
                                                   &force_verify);
                if (ret < 0)
                    goto end2;
                VERBOSE_LOG(stderr, "inserted %d\n"
                            "--------------------------------------------------"
                            "\n",
                            key);
            } else {
                VERBOSE_LOG(log, "del %d\n", key);
                ret = auto_test_cross_check_update(contctx1, contctx2, tp,
                                                   &do_auto_test_delete, key, 0,
                                                   1, 1, 0, 0, contp->confirm,
                                                   &force_verify);
                if (ret < 0)
                    goto end2;
                VERBOSE_LOG(stderr, "deleted %d\n"
                            "--------------------------------------------------"
                            "\n",
                            key);
            }
        }

        if (contp->verify) {
            if (force_verify == 1)
                ret = (*(contctx1->cb.verify_rand))(contctx1);
            else if (force_verify == 2)
                ret = (*(contctx2->cb.verify_rand))(contctx2);
            else if (!(random() % contp->verification_period))
                ret = (*(contctx1->cb.verify_cmp))(contctx1, contctx2, ctx);
            if (ret != 0)
                break;
        }

        if (contp->verbose_stats)
            refresh_stat_output(contctx1);
    }

end2:
    thread_pool_free(tp);
end1:
    restore_default_handler(SIGINT);
    restore_default_handler(SIGTERM);
    restore_default_handler(SIGUSR1);
    restore_default_handler(SIGUSR2);
    return ret;
}

/* vi: set expandtab sw=4 ts=4: */
