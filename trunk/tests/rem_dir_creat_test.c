/*
 * rem_dir_creat_test.c
 */

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#define DIR_NAME "test_1"
#define FILE_NAME "test_2"

#define DIR_MODE (S_IRWXU | S_IRWXG | S_IRWXO)
#define FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

static int test_mknod(const char *, mode_t);
static int test_mkdir(const char *, mode_t);
static int test_opendir(const char *);
static int test_unlinkat(int, const char *, int);
static int test_rmdir(const char *);

static int do_creat_at(int, const char *, mode_t, void *);
static int do_mkdir_at(int, const char *, mode_t, void *);
static int do_link_at(int, const char *, mode_t, void *);
static int do_rename_at(int, const char *, mode_t, void *);
static int do_symlink_at(int, const char *, mode_t, void *);

static int
handle_error(const char *func)
{
    error(0, errno, "%s()", func);
    return -1;
}

static int
test_mknod(const char *name, mode_t mode)
{
    int fd;

    fd = open(name, O_CREAT | O_EXCL | O_RDONLY, mode);
    if (fd == -1)
        return handle_error("open");

    close(fd);

    return 0;
}

static int
test_mkdir(const char *name, mode_t mode)
{
    return (mkdir(name, mode) == -1) ? handle_error("mkdir") : 0;
}

static int
test_opendir(const char *name)
{
    int fd;

    fd = open(name, O_DIRECTORY | O_RDONLY);
    return (fd == -1) ? handle_error("open") : fd;
}

static int
test_unlinkat(int dfd, const char *name, int flag)
{
    return (unlinkat(dfd, name, flag) == -1) ? handle_error("unlinkat") : 0;
}

static int
test_rmdir(const char *name)
{
    return (rmdir(name) == -1) ? handle_error("rmdir") : 0;
}

static int
do_creat_at(int dfd, const char *name, mode_t mode, void *ctx)
{
    int fd;

    (void)ctx;

    fd = openat(dfd, name, O_CREAT | O_EXCL | O_RDONLY, mode);
    if (fd == -1)
        return -1;

    close(fd);

    return 0;
}

static int
do_mkdir_at(int dfd, const char *name, mode_t mode, void *ctx)
{
    (void)ctx;

    return mkdirat(dfd, name, mode);
}

static int
do_link_at(int dfd, const char *name, mode_t mode, void *ctx)
{
    (void)mode;

    return linkat(AT_FDCWD, (const char *)ctx, dfd, name, 0);
}

static int
do_rename_at(int dfd, const char *name, mode_t mode, void *ctx)
{
    (void)mode;

    return renameat(AT_FDCWD, (const char *)ctx, dfd, name);
}

static int
do_symlink_at(int dfd, const char *name, mode_t mode, void *ctx)
{
    (void)mode;
    (void)ctx;

    return symlinkat(_PATH_DEVNULL, dfd, name);
}

int
main(int argc, char **argv)
{
    int dfd;
    size_t i;

    static const struct ent {
        const char  *nm;
        int         (*fn)(int, const char *, mode_t, void *);
        void        *ctx;
        int         unlinkat_flags;
    } tests[] = {
        {"openat",      &do_creat_at,   NULL,       0},
        {"mkdirat",     &do_mkdir_at,   NULL,       AT_REMOVEDIR},
        {"linkat",      &do_link_at,    FILE_NAME,  0},
        {"renameat",    &do_rename_at,  FILE_NAME,  0},
        {"symlinkat",   &do_symlink_at, NULL,       0}
    };
    const struct ent *t;

    (void)argc;
    (void)argv;

    if (test_mkdir(DIR_NAME, DIR_MODE) == -1)
        goto err1;

    dfd = test_opendir(DIR_NAME);
    if (dfd == -1)
        goto err2;

    if (test_mknod(FILE_NAME, FILE_MODE) == -1)
        goto err3;

    /* verify namespace operations in directory without removing */
    for (i = 0; i < ARRAY_SIZE(tests); i++) {
        t = &tests[i];

        if ((t->fn)(dfd, FILE_NAME, FILE_MODE, t->ctx) == -1) {
            handle_error(t->nm);
            goto err4;
        }

        if (test_unlinkat(dfd, FILE_NAME, t->unlinkat_flags) == -1)
            goto err5;
    }

    if (test_rmdir(DIR_NAME) == -1)
        goto err3;

    if (test_mknod(FILE_NAME, FILE_MODE) == -1)
        goto err3;

    /* verify namepsace operations in directory after removing */
    for (i = 0; i < ARRAY_SIZE(tests); i++) {
        t = &tests[i];

        if ((t->fn)(dfd, FILE_NAME, FILE_MODE, t->ctx) == 0) {
            unlinkat(dfd, FILE_NAME, t->unlinkat_flags);
            goto err5; /* POSIX-1.2008 specifies error for this case */
        }

        handle_error(t->nm);
    }

    unlink(FILE_NAME);

    close(dfd);

    return EXIT_SUCCESS;

err5:
    unlink(FILE_NAME);
    close(dfd);
    return EXIT_FAILURE;

err4:
    unlink(FILE_NAME);
err3:
    close(dfd);
err2:
    rmdir(DIR_NAME);
err1:
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
