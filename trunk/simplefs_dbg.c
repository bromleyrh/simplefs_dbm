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
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DB_PATHNAME "fs.db"

enum op {
    OP_FIX_UP = 1
};

static volatile sig_atomic_t quit;

#define OBJSZ(obj) sizeof(struct db_obj_##obj)

static void print_usage(const char *);
static int parse_cmdline(int, char **, enum op *, const char **, int *);

static void int_handler(int);

static int uint64_cmp(uint64_t, uint64_t);
static int db_key_cmp(const void *, const void *, void *);

static void disp_header(FILE *, const struct db_key *, const void *, size_t);
static void disp_free_ino(FILE *, const struct db_key *, const void *, size_t);
static void disp_dirent(FILE *, const struct db_key *, const void *, size_t);
static void disp_stat(FILE *, const struct db_key *, const void *, size_t);
static void disp_page(FILE *, const struct db_key *, const void *, size_t);
static void disp_xattr(FILE *, const struct db_key *, const void *, size_t);
static void disp_ulinked_inode(FILE *, const struct db_key *, const void *,
                               size_t);

static int dump_db_obj(FILE *, const void *, const void *, size_t, const char *,
                       void *);

static int dump_cb(const void *, const void *, size_t, void *);

static int dump_db(FILE *, struct dbh *);

static int cmd_dump(struct dbh *);
static int cmd_find(struct dbh *);
static int cmd_help(struct dbh *);
static int cmd_insert(struct dbh *);
static int cmd_remove(struct dbh *);
static int cmd_update(struct dbh *);

static int process_cmd(struct dbh *);

static int do_fix_up_interactive(const char *, int);

static void
print_usage(const char *prognm)
{
    printf("Usage: %s [options]\n"
           "\n"
           "    -F PATH use specified database file path\n"
           "    -f      fix up file system metadata\n"
           "    -h      output help\n"
           "    -w      open database file for writing (default is to open for "
           "reading only)\n",
           prognm);
}

static int
parse_cmdline(int argc, char **argv, enum op *op, const char **db_pathname,
              int *ro)
{
    for (;;) {
        int opt = getopt(argc, argv, "F:fhw");

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
        case 'w':
            *ro = 0;
            break;
        default:
            return -1;
        }
    }

    return 0;
}

static void
int_handler(int signum)
{
    (void)signum;

    quit = 1;
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

static void
disp_header(FILE *f, const struct db_key *key, const void *data,
            size_t datasize)
{
    struct db_obj_header *hdr = (struct db_obj_header *)data;

    (void)key;
    (void)datasize;

    fprintf(f, "I-node count %" PRIu64, hdr->numinodes);
}

static void
disp_free_ino(FILE *f, const struct db_key *key, const void *data,
              size_t datasize)
{
    (void)data;
    (void)datasize;

    fprintf(f, "number %" PRIu64 " to %" PRIu64,
            (uint64_t)(key->ino), (uint64_t)(key->ino) + FREE_INO_RANGE_SZ - 1);
}

static void
disp_dirent(FILE *f, const struct db_key *key, const void *data,
            size_t datasize)
{
    struct db_obj_dirent *de = (struct db_obj_dirent *)data;

    (void)datasize;

    fprintf(f, "directory %" PRIu64 ", name %s -> node %" PRIu64,
            (uint64_t)(key->ino), key->name, (uint64_t)(de->ino));
}

static void
disp_stat(FILE *f, const struct db_key *key, const void *data, size_t datasize)
{
    struct db_obj_stat *s = (struct db_obj_stat *)data;

    (void)datasize;

    fprintf(f, "node %" PRIu64 " -> st_ino %" PRIu64,
            (uint64_t)(key->ino), (uint64_t)(s->st_ino));
}

static void
disp_page(FILE *f, const struct db_key *key, const void *data, size_t datasize)
{
    (void)data;

    fprintf(f, "node %" PRIu64 ", page %" PRIu64 ", size %zu",
            (uint64_t)(key->ino), (uint64_t)(key->pgno), datasize);
}

static void
disp_xattr(FILE *f, const struct db_key *key, const void *data, size_t datasize)
{
    (void)data;

    fprintf(f, "node %" PRIu64 ", name %s, size %zu",
            (uint64_t)(key->ino), key->name, datasize);
}

static void
disp_ulinked_inode(FILE *f, const struct db_key *key, const void *data,
                   size_t datasize)
{
    (void)data;
    (void)datasize;

    fprintf(f, "node %" PRIu64,
            (uint64_t)(key->ino));
}

static int
dump_db_obj(FILE *f, const void *key, const void *data, size_t datasize,
            const char *prefix, void *ctx)
{
    struct db_key *k = (struct db_key *)key;

    static const struct {
        const char  *dispstr;
        size_t      datasize;
        void        (*datadisp)(FILE *, const struct db_key *, const void *,
                                size_t);
    } objinfo[] = {
        [TYPE_HEADER]           = {"Header",
                                   OBJSZ(header),  &disp_header},
        [TYPE_FREE_INO]         = {"Free I-node number information",
                                   0,              &disp_free_ino},
        [TYPE_DIRENT]           = {"Directory entry",
                                   OBJSZ(dirent),  &disp_dirent},
        [TYPE_STAT]             = {"I-node entry",
                                   OBJSZ(stat),    &disp_stat},
        [TYPE_PAGE]             = {"Page",
                                   0,              &disp_page},
        [TYPE_XATTR]            = {"Extended attribute entry",
                                   0,              &disp_xattr},
        [TYPE_ULINKED_INODE]    = {"Unlinked I-node entry",
                                   0,              &disp_ulinked_inode}
    }, *objinfop;

    (void)ctx;

    if (k->type >= ARRAY_SIZE(objinfo))
        goto type_err;

    objinfop = &objinfo[k->type];
    if (objinfop->datadisp == NULL)
        goto type_err;

    if ((objinfop->datasize != 0) && (datasize != objinfop->datasize)) {
        fprintf(stderr, "%s data size %zu incorrect\n", objinfop->dispstr,
                datasize);
        return -EILSEQ;
    }

    fprintf(f, "%s%s: ", prefix, objinfop->dispstr);
    (*(objinfop->datadisp))(f, k, data, datasize);
    fputc('\n', f);

    return 0;

type_err:
    fprintf(stderr, "Invalid object type %d\n", k->type);
    return -EILSEQ;
}

static int
dump_cb(const void *key, const void *data, size_t datasize, void *ctx)
{
    if (quit)
        return 1;

    return dump_db_obj((FILE *)ctx, key, data, datasize, "", NULL);
}

static int
dump_db(FILE *f, struct dbh *dbh)
{
    return db_hl_walk(dbh, &dump_cb, f);
}

static int
cmd_dump(struct dbh *dbh)
{
    char *path;
    FILE *f;
    int err;
    struct sigaction oldsa;

    static const struct sigaction sa = {
        .sa_handler = &int_handler
    };

    path = readline("Output file name: ");
    if (path == NULL)
        return 0;

    f = fopen(path, "w");
    if (f == NULL) {
        err = -errno;
        error(0, -err, "Error opening %s", path);
        goto err1;
    }

    if (sigaction(SIGINT, &sa, &oldsa) == -1) {
        err = -errno;
        goto err2;
    }

    fputs("Dumping...", stderr);

    err = dump_db(f, dbh);
    fputc('\n', stderr);
    if (err) {
        if (err == 1) {
            fputs("Dump interrupted\n", stderr);
            err = 2;
        }
        goto err3;
    }

    if (sigaction(SIGINT, &oldsa, NULL) == -1) {
        err = -errno;
        goto err2;
    }

    if ((fflush(f) != 0) || (fsync(fileno(f)) == -1)) {
        err = -errno;
        error(0, -err, "Error writing %s", path);
        goto err2;
    }

    if (fclose(f) != 0) {
        err = -errno;
        error(0, -err, "Error closing %s", path);
        goto err1;
    }

    free(path);

    fputs("Dump file written\n", stderr);

    return 0;

err3:
    sigaction(SIGINT, &oldsa, NULL);
err2:
    fclose(f);
err1:
    free(path);
    return err;
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
do_fix_up_interactive(const char *db_pathname, int ro)
{
    int ret;
    struct dbh *dbh;

    ret = db_hl_open(&dbh, db_pathname, sizeof(struct db_key), &db_key_cmp,
                     NULL, ro ? DB_HL_RDONLY : 0);
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
    int ro = 1;

    ret = parse_cmdline(argc, argv, &op, &db_pathname, &ro);
    if (ret != 0)
        return (ret == -2) ? EXIT_SUCCESS : EXIT_FAILURE;
    if (op == 0) {
        fputs("Must specify operation\n", stderr);
        return EXIT_FAILURE;
    }

    switch (op) {
    case OP_FIX_UP:
        ret = do_fix_up_interactive(db_pathname, ro);
        break;
    default:
        ret = -EIO;
    }

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
