/*
 * simplefs_dbg.c
 */

#define _GNU_SOURCE

#include "obj.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <dbm_high_level.h>

#include <files/util.h>

#include <readline/history.h>
#include <readline/readline.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DB_PATHNAME "fs.db"

enum op {
    OP_FIX_UP = 1
};

static int parse_cmdline(int, char **, enum op *, const char **);

static int uint64_cmp(uint64_t, uint64_t);
static int db_key_cmp(const void *, const void *, void *);

static int cmd_dump(struct dbh *);
static int cmd_find(struct dbh *);
static int cmd_help(struct dbh *);
static int cmd_insert(struct dbh *);
static int cmd_remove(struct dbh *);
static int cmd_update(struct dbh *);

static int process_cmd(struct dbh *);

static int do_fix_up_interactive(const char *);

static void
print_usage(const char *prognm)
{
    printf("Usage: %s [options]\n"
           "\n"
           "    -F PATH use specified database file path\n"
           "    -f      fix up file system metadata\n"
           "    -h      output help\n",
           prognm);
}

static int
parse_cmdline(int argc, char **argv, enum op *op, const char **db_pathname)
{
    for (;;) {
        int opt = getopt(argc, argv, "F:fh");

        if (opt == -1)
            break;

        switch (opt) {
        case 'F':
            *db_pathname = optarg;
            break;
        case 'f':
            *op = OP_FIX_UP;
            break;
        case 'h':
            print_usage(argv[0]);
            return -2;
        default:
            return -1;
        }
    }

    return 0;
}

static int
uint64_cmp(uint64_t n1, uint64_t n2)
{
    return (n1 > n2) - (n1 < n2);
}

static int
db_key_cmp(const void *k1, const void *k2, void *key_ctx)
{
    int cmp;
    struct db_key *key1 = (struct db_key *)k1;
    struct db_key *key2 = (struct db_key *)k2;

    (void)key_ctx;

    cmp = uint64_cmp(key1->type, key2->type);
    if ((cmp != 0) || (key1->type == TYPE_HEADER))
        return cmp;

    cmp = uint64_cmp(key1->ino, key2->ino);
    if (cmp != 0)
        return cmp;

    switch (key1->type) {
    case TYPE_DIRENT:
    case TYPE_XATTR:
        cmp = strcmp(key1->name, key2->name);
        break;
    case TYPE_PAGE:
        cmp = uint64_cmp(key1->pgno, key2->pgno);
    case TYPE_FREE_INO:
    case TYPE_STAT:
    case TYPE_ULINKED_INODE:
        break;
    default:
        abort();
    }

    return cmp;
}

static int
cmd_dump(struct dbh *dbh)
{
    (void)dbh;

    return 0;
}

static int
cmd_find(struct dbh *dbh)
{
    (void)dbh;

    return 0;
}

static int
cmd_help(struct dbh *dbh)
{
    (void)dbh;

    fputs("Commands:\n"
          "\n"
          "    dump\n"
          "    find\n"
          "    help\n"
          "    insert\n"
          "    quit\n"
          "    remove\n"
          "    update\n",
          stdout);

    return 0;
}

static int
cmd_insert(struct dbh *dbh)
{
    (void)dbh;

    return 0;
}

static int
cmd_quit(struct dbh *dbh)
{
    (void)dbh;

    return 1;
}

static int
cmd_remove(struct dbh *dbh)
{
    (void)dbh;

    return 0;
}

static int
cmd_update(struct dbh *dbh)
{
    (void)dbh;

    return 0;
}

static int
process_cmd(struct dbh *dbh)
{
    char *cmd;
    unsigned char i;

    static const struct {
        const char  *cmd;
        int         (*fn)(struct dbh *);
    } cmds[] = {
        [(unsigned char)'d'] = {"dump",    &cmd_dump},
        [(unsigned char)'f'] = {"find",    &cmd_find},
        [(unsigned char)'i'] = {"insert",  &cmd_insert},
        [(unsigned char)'h'] = {"help",    &cmd_help},
        [(unsigned char)'q'] = {"quit",    &cmd_quit},
        [(unsigned char)'r'] = {"remove",  &cmd_remove},
        [(unsigned char)'u'] = {"update",  &cmd_update}
    }, *cmdp;

    cmd = readline("Command: ");
    if (cmd == NULL) {
        fputc('\n', stdout);
        return 1;
    }

    i = (unsigned char)(cmd[0]);
    if (i >= ARRAY_SIZE(cmds))
        goto input_err;

    cmdp = &cmds[i];
    if ((cmdp->cmd == NULL) || (strcmp(cmdp->cmd, cmd) != 0))
        goto input_err;

    free(cmd);

    return (*(cmdp->fn))(dbh);

input_err:
    fprintf(stderr, "Unrecognized command \"%s\"\n", cmd);
    free(cmd);
    return 2;
}

static int
do_fix_up_interactive(const char *db_pathname)
{
    int ret;
    struct dbh *dbh;

    ret = db_hl_open(&dbh, db_pathname, sizeof(struct db_key), &db_key_cmp,
                     NULL, 0);
    if (ret != 0)
        return ret;

    for (;;) {
        ret = process_cmd(dbh);
        switch (ret) {
        case 0:
        case 2:
            continue;
        case 1:
            goto end;
        default:
            goto err;
        }
    }

end:
    db_hl_close(dbh);
    return 0;

err:
    db_hl_close(dbh);
    return ret;
}

int
main(int argc, char **argv)
{
    const char *db_pathname = DB_PATHNAME;
    enum op op = 0;
    int ret;

    ret = parse_cmdline(argc, argv, &op, &db_pathname);
    if (ret != 0)
        return (ret == -2) ? EXIT_SUCCESS : EXIT_FAILURE;
    if (op == 0) {
        fputs("Must specify operation\n", stderr);
        return EXIT_FAILURE;
    }

    switch (op) {
    case OP_FIX_UP:
        ret = do_fix_up_interactive(db_pathname);
        break;
    default:
        ret = -EIO;
    }

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
