/*
 * simplefs_dbg.c
 */

#define _GNU_SOURCE

#include "config.h"

#include "obj.h"
#include "util.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <dbm_high_level.h>
#include <strings_ext.h>

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

#ifdef HAVE_STRUCT_STAT_ST_MTIMESPEC
#define st_atim st_atimespec
#define st_mtim st_mtimespec
#define st_ctim st_ctimespec
#endif

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

static int get_key_ino(struct db_key *);
static int get_key_ino_name(struct db_key *);
static int get_key_ino_pgno(struct db_key *);

static void disp_header(FILE *, const struct db_key *, const void *, size_t);
static void disp_header_full(FILE *, const struct db_key *, const void *,
                             size_t);
static void disp_free_ino(FILE *, const struct db_key *, const void *, size_t);
static void disp_dirent(FILE *, const struct db_key *, const void *, size_t);
static void disp_stat(FILE *, const struct db_key *, const void *, size_t);
static void disp_stat_full(FILE *, const struct db_key *, const void *, size_t);
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

static int
get_key_ino(struct db_key *k)
{
    char *arg;

    arg = readline("I-node: ");
    if (arg == NULL)
        return 2;

    k->ino = (uint64_t)strtoul(arg, NULL, 10);

    free(arg);

    return 0;
}

static int
get_key_ino_name(struct db_key *k)
{
    char *arg;
    int ret;

    ret = get_key_ino(k);
    if (ret != 0)
        return ret;

    arg = readline("Name: ");
    if (arg == NULL)
        return 2;

    strlcpy(k->name, arg, sizeof(k->name));

    free(arg);

    return 0;
}

static int
get_key_ino_pgno(struct db_key *k)
{
    char *arg;
    int ret;

    ret = get_key_ino(k);
    if (ret != 0)
        return ret;

    arg = readline("Page: ");
    if (arg == NULL)
        return 2;

    k->pgno = strtoull(arg, NULL, 10);

    free(arg);

    return 0;
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
disp_header_full(FILE *f, const struct db_key *key, const void *data,
                 size_t datasize)
{
    struct db_obj_header *hdr = (struct db_obj_header *)data;

    (void)key;
    (void)datasize;

    fprintf(f,
            "     Version %" PRIu64 "\n"
            "I-node count %" PRIu64,
            hdr->version,
            hdr->numinodes);
}

static void
disp_free_ino(FILE *f, const struct db_key *key, const void *data,
              size_t datasize)
{
    (void)data;
    (void)datasize;

    fprintf(f, "number %" PRIu64 " to %" PRIu64,
            key->ino, key->ino + FREE_INO_RANGE_SZ - 1);
}

static void
disp_dirent(FILE *f, const struct db_key *key, const void *data,
            size_t datasize)
{
    struct db_obj_dirent *de = (struct db_obj_dirent *)data;

    (void)datasize;

    fprintf(f, "directory %" PRIu64 ", name %s -> node %" PRIu64,
            key->ino, key->name, de->ino);
}

static void
disp_stat(FILE *f, const struct db_key *key, const void *data, size_t datasize)
{
    struct db_obj_stat *s = (struct db_obj_stat *)data;

    (void)datasize;

    fprintf(f, "node %" PRIu64 " -> st_ino %" PRIu64,
            key->ino, s->st_ino);
}

static void
disp_stat_full(FILE *f, const struct db_key *key, const void *data,
               size_t datasize)
{
    char atim[26], ctim[26], mtim[26];
    struct db_obj_stat *s = (struct db_obj_stat *)data;

    (void)datasize;

    fprintf(f,
            "node %" PRIu64 " ->\n"
            "    st_dev     %" PRIu64 "\n"
            "    st_ino     %" PRIu64 "\n"
            "    st_mode    %" PRIo32 "\n"
            "    st_nlink   %" PRIu32 "\n"
            "    st_uid     %" PRIu32 "\n"
            "    st_gid     %" PRIu32 "\n"
            "    st_rdev    %" PRIu64 "\n"
            "    st_size    %" PRIi64 "\n"
            "    st_blksize %" PRIi64 "\n"
            "    st_blocks  %" PRIi64 "\n"
            "    st_atim    %s"
            "    st_mtim    %s"
            "    st_ctim    %s"
            "    num_ents   %" PRIu32,
            key->ino,
            s->st_dev,
            s->st_ino,
            s->st_mode,
            s->st_nlink,
            s->st_uid,
            s->st_gid,
            s->st_rdev,
            s->st_size,
            s->st_blksize,
            s->st_blocks,
            ctime_r((const time_t *)&(s->st_atim), atim),
            ctime_r((const time_t *)&(s->st_mtim), mtim),
            ctime_r((const time_t *)&(s->st_ctim), ctim),
            s->num_ents);
}

static void
disp_page(FILE *f, const struct db_key *key, const void *data, size_t datasize)
{
    (void)data;

    fprintf(f, "node %" PRIu64 ", page %" PRIu64 ", size %zu",
            key->ino, key->pgno, datasize);
}

static void
disp_xattr(FILE *f, const struct db_key *key, const void *data, size_t datasize)
{
    (void)data;

    fprintf(f, "node %" PRIu64 ", name %s, size %zu",
            key->ino, key->name, datasize);
}

static void
disp_ulinked_inode(FILE *f, const struct db_key *key, const void *data,
                   size_t datasize)
{
    (void)data;
    (void)datasize;

    fprintf(f, "node %" PRIu64,
            key->ino);
}

static int
dump_db_obj(FILE *f, const void *key, const void *data, size_t datasize,
            const char *prefix, void *ctx)
{
    struct db_key *k = (struct db_key *)key;

    static const struct {
        const char  *dispstr;
        size_t      datasize;
        void        (*disp_data)(FILE *, const struct db_key *, const void *,
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
    if (objinfop->disp_data == NULL)
        goto type_err;

    if ((objinfop->datasize != 0) && (datasize != objinfop->datasize)) {
        error(0, 0, "%s data size %zu incorrect\n", objinfop->dispstr,
              datasize);
        return -EILSEQ;
    }

    fprintf(f, "%s%s: ", prefix, objinfop->dispstr);
    (*(objinfop->disp_data))(f, k, data, datasize);
    fputc('\n', f);

    return 0;

type_err:
    error(0, 0, "Invalid object type %d", k->type);
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
    char *arg;
    enum db_obj_type type;
    int res;
    size_t datasize;
    size_t i;
    struct db_key k;
    union {
        struct db_obj_header    hdr;
        struct db_obj_dirent    de;
        struct db_obj_stat      s;
        struct db_obj_free_ino  freeino;
    } data;
    void *d;

    static const struct {
        const char          *nm;
        size_t              datasize;
        int                 (*get_args)(struct db_key *);
        void                (*disp_data)(FILE *, const struct db_key *,
                                         const void *, size_t);
    } typemap[] = {
        [TYPE_HEADER]           = {"TYPE_HEADER",           OBJSZ(header),
                                   NULL,
                                   &disp_header_full},
        [TYPE_DIRENT]           = {"TYPE_DIRENT",           OBJSZ(dirent),
                                   &get_key_ino_name,
                                   &disp_dirent},
        [TYPE_STAT]             = {"TYPE_STAT",             OBJSZ(stat),
                                   &get_key_ino,
                                   &disp_stat_full},
        [TYPE_PAGE]             = {"TYPE_PAGE",             0,
                                   &get_key_ino_pgno,
                                   &disp_page},
        [TYPE_XATTR]            = {"TYPE_XATTR",            0,
                                   &get_key_ino_name,
                                   &disp_xattr},
        [TYPE_ULINKED_INODE]    = {"TYPE_ULINKED_INODE",    0,
                                   &get_key_ino,
                                   &disp_ulinked_inode},
        [TYPE_FREE_INO]         = {"TYPE_FREE_INO",         OBJSZ(free_ino),
                                   &get_key_ino,
                                   &disp_free_ino}
    }, *typep;

    for (i = 0; i < ARRAY_SIZE(typemap); i++) {
        typep = &typemap[i];

        if (typep->nm != NULL)
            fprintf(stderr, "%zu: %s\n", i, typep->nm);
    }

    arg = readline("Type: ");
    if (arg == NULL)
        return 1;
    type = atoi(arg);
    free(arg);

    if (type >= ARRAY_SIZE(typemap))
        goto type_err;

    typep = &typemap[type];
    if (typep->disp_data == NULL)
        goto type_err;

    if (typep->get_args != NULL) {
        res = (*(typep->get_args))(&k);
        if (res != 0)
            return res;
    }
    k.type = type;

    if (typep->datasize == 0) {
        res = db_hl_search(dbh, &k, NULL, NULL, &datasize);
        if (res != 1)
            goto lookup_err;

        d = do_malloc(datasize);
        if (d == NULL) {
            res = -errno;
            error(0, 0, "Out of memory");
            return res;
        }
    } else
        d = &data;

    res = db_hl_search(dbh, &k, &k, d, &datasize);
    if (res != 1)
        goto lookup_err;

    (*(typep->disp_data))(stdout, &k, d, datasize);
    putchar('\n');

    if (typep->datasize == 0)
        free(d);

    return 0;

lookup_err:
    if (res == 0)
        res = 2;
    else
        error(0, -res, "Error looking up");
    return res;

type_err:
    error(0, 0, "Invalid object type %d", type);
    return 2;
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
          "    update\n"
          "\n",
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
    error(0, 0, "Unrecognized command \"%s\"", cmd);
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
    if (op == 0)
        error(EXIT_FAILURE, 0, "Must specify operation");

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
