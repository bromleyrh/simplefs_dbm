/*
 * fuse_cache_test.c
 */

#include "test_util_cont.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <test_util.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct test_opts {
    struct cont_test_opts   testopts;
    int                     *test_type;
    uint32_t                *max_data_len;
};

struct params {
    struct cont_params  contp;
    uint32_t            max_data_len;
};

struct fuse_cache_ctx {
    struct cont_ctx contctx;
    void            *cache;
    uint32_t        max_data_len;
};

static int parse_test_opt(int, void *);
static int parse_cmdline(int, char **, int *, struct params *, int *,
                         uint32_t *);

static int run_automated_test(int, const struct params *);

static int
parse_test_opt(int opt, void *test_opts)
{
    struct test_opts *testopts = (struct test_opts *)test_opts;

    switch (opt) {
    case 'K':
        *(testopts->max_data_len) = strtoul(optarg, NULL, 10);
        break;
    default:
        return -1;
    }

    return 0;
}

static int
parse_cmdline(int argc, char **argv, int *seed, struct params *p,
              int *test_type, uint32_t *max_data_len)
{
    struct test_opts testopts = {
        .test_type      = test_type,
        .max_data_len   = max_data_len
    };

    static const char progusage[] = {
        "    -K SIZE   generate data with length no greater than the given "
        "size in bytes\n"
    };

    return parse_cont_test_cmdline(argc, argv, progusage, "K:", &parse_test_opt,
                                   (struct cont_params *)p,
                                   (struct cont_test_opts *)&testopts, seed,
                                   NULL, NULL, NULL, 0);
}

static int
run_automated_test(int test_type, const struct params *p)
{
    const struct cont_params *contp = &p->contp;
    int ret, tmp;
    struct bitmap_data bmdata;
    struct fuse_cache_ctx cachectx;

    ret = init_bitmap(&bmdata, contp->max_key);
    if (ret != 0) {
        error(0, -ret, "Error initializing test bitmap");
        return -1;
    }

    ret = init_fuse_cache_ctx(&cachectx, p->max_data_len, &bmdata,
                              contp->key_size, contp->max_key);
    if (ret != 0)
        goto end;

    switch (test_type) {
    case 3:
        ret = cont_test_rand_repeat((struct cont_ctx *)&cachectx,
                                    (const struct cont_params *)p, NULL);
        break;
    case 4:
        ret = cont_test_sorted((struct cont_ctx *)&cachectx,
                               (const struct cont_params *)p, NULL);
        break;
    case 5:
        ret = cont_test_rand_norepeat((struct cont_ctx *)&cachectx,
                                      (const struct cont_params *)p, NULL);
        break;
    default:
        ret = -EIO;
    }

    if (ret != 0)
        goto end;

    switch (test_type) {
    case 3:
    case 4:
        /* XXX */
        if (contp->use_cont) {
            ret = contp->use_bitmap
                  ? verify_rand((struct cont_ctx *)&cachectx)
                  : walk_be(&cachectx, 1);
        } else if (contp->use_bitmap) {
            print_bitmap(stdout,
                         (struct bitmap_data *)&cachectx.contctx.bmdata);
        }
        break;
    case 5:
        ret = verify_rand((struct cont_ctx *)&cachectx);
        break;
    default:
        ret = -EIO;
    }

    if (ret != -EIO) {
        tmp = destroy_fuse_cache_ctx(&cachectx);
        if (ret == 0)
            ret = tmp;
    }

end:
    free_bitmap(&bmdata);
    return ret ? -1 : 0;
}

int
main(int argc, char **argv)
{
    int ret;
    int seed = get_seed();
    int test_type = 3;

    static struct params p = {
        .contp = {
            .insert_ratio           = 4,
            .key_size               = sizeof(int),
            .max_key                = 128 * 1024,
            .num_ops                = ULLONG_MAX,
            .search_period          = 128,
            .verification_period    = 1024 * 1024,
            .test_replace           = 1,
            .test_iter              = 1,
            .use_bitmap             = 1,
            .use_cont               = 1,
            .zero_keys              = 1
        }
    };

    ret = parse_cmdline(argc, argv, &seed, &p, &test_type, &p.max_data_len);
    if (ret != 0)
        return (ret == -1) ? EXIT_FAILURE : EXIT_SUCCESS;

    if (init_test(argc, argv, seed, 0, 0, 0) == -1)
        return EXIT_FAILURE;

    ret = run_automated_test(test_type, &p);

    if (end_test(argc, argv, seed, (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE)
        != 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
