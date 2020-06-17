/*
 * simplefs_dbg.c
 */

#define _GNU_SOURCE
#define _XOPEN_SOURCE

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
#include <time.h>
#include <unistd.h>

#include <sys/param.h>

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

static int confirm_del_hdr(struct db_key *);
static int get_key_ino(struct db_key *);
static int get_key_ino_name(struct db_key *);
static int get_key_ino_pgno(struct db_key *);

static int scan_int(char *, void *, size_t, int, int, int);
static int scan_time(char *, void *, size_t, int, int, int);

static int set_header(const struct db_key *, void **, size_t *);
static int set_free_ino(const struct db_key *, void **, size_t *);
static int set_dirent(const struct db_key *, void **, size_t *);
static int set_stat(const struct db_key *, void **, size_t *);
static int set_page(const struct db_key *, void **, size_t *);
static int set_xattr(const struct db_key *, void **, size_t *);
static int set_ulinked_inode(const struct db_key *, void **, size_t *);

static void disp_header(FILE *, const struct db_key *, const void *, size_t);
static void disp_header_full(FILE *, const struct db_key *, const void *,
                             size_t);
static void disp_free_ino(FILE *, const struct db_key *, const void *, size_t);
static void disp_free_ino_full(FILE *, const struct db_key *, const void *,
                               size_t);
static void disp_dirent(FILE *, const struct db_key *, const void *, size_t);
static void disp_stat(FILE *, const struct db_key *, const void *, size_t);
static void disp_stat_full(FILE *, const struct db_key *, const void *, size_t);
static void disp_page(FILE *, const struct db_key *, const void *, size_t);
static void disp_xattr(FILE *, const struct db_key *, const void *, size_t);
static void disp_ulinked_inode(FILE *, const struct db_key *, const void *,
                               size_t);

static int used_ino_get(uint64_t *, uint32_t, uint32_t);

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
confirm_del_hdr(struct db_key *k)
{
    char *arg;
    int ret;

    (void)k;

    arg = readline("Warning: Deleting file system header object. "
                   "Proceed with operation? (y/n) ");
    if (arg == NULL)
        return 2;

    ret = ((arg[0] == 'y') || (arg[0] == 'Y')) ? 0 : 2;

    free(arg);

    return ret;
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

static int
scan_int(char *str, void *data, size_t off, int is_signed, int width, int base)
{
    char convspec, typemod;
    char fmt[16];
    size_t i;

    static const struct {
        size_t  size_signed;
        size_t  size_unsigned;
        char    typemod;
    } sizeinfo[] = {
        {sizeof(int),       sizeof(unsigned),           '\0'},
        {sizeof(long long), sizeof(unsigned long long), 'L'}
    }, *sizeinfop;

    switch (base) {
    case 8:
        convspec = 'o';
        break;
    case 10:
        convspec = is_signed ? 'd' : 'u';
        break;
    default:
        return -EINVAL;
    }

    for (i = 0;; i++) {
        if (i == ARRAY_SIZE(sizeinfo))
            return -EINVAL;
        sizeinfop = &sizeinfo[i];

        if (width == (int)(is_signed
                           ? sizeinfop->size_signed
                           : sizeinfop->size_unsigned)) {
            typemod = sizeinfop->typemod;
            break;
        }
    }

    i = 1;
    fmt[0] = '%';
    if (typemod != '\0')
        fmt[i++] = typemod;
    fmt[i] = convspec;
    fmt[i+1] = '\0';

    return (sscanf(str, fmt, (char *)data + off) == 1) ? 0 : 2;
}

static int
scan_time(char *str, void *data, size_t off, int is_signed, int width, int base)
{
    struct disk_timespec *ts;
    struct tm tm;

    (void)is_signed;
    (void)width;
    (void)base;

    memset(&tm, 0, sizeof(tm));
    if (strptime(str, "%Y-%m-%d %H:%M:%S", &tm) == NULL)
        return 2;
    tm.tm_isdst = -1;

    ts = (struct disk_timespec *)((char *)data + off);
    ts->tv_sec = mktime(&tm);
    ts->tv_nsec = 0;

    return 0;
}

static int
set_header(const struct db_key *key, void **data, size_t *datasize)
{
    (void)key;
    (void)data;
    (void)datasize;

    return 0;
}

static int
set_free_ino(const struct db_key *key, void **data, size_t *datasize)
{
    (void)key;
    (void)data;
    (void)datasize;

    return 0;
}

static int
set_dirent(const struct db_key *key, void **data, size_t *datasize)
{
    (void)key;
    (void)data;
    (void)datasize;

    return 0;
}

#define STATOFF(field) offsetof(struct db_obj_stat, field)

static int
set_stat(const struct db_key *key, void **data, size_t *datasize)
{
    char *arg;
    int ret;
    size_t i;
    struct db_obj_stat *s = *(struct db_obj_stat **)data;

    static const struct {
        const char  *nm;
        size_t      statoff;
        int         (*scan_field)(char *, void *, size_t, int, int, int);
        int         is_signed;
        int         width;
        int         base;
    } scandescs[] = {
        {"st_dev",      STATOFF(st_dev),        &scan_int,  0, 8, 10},
        {"st_ino",      STATOFF(st_ino),        &scan_int,  0, 8, 10},
        {"st_mode",     STATOFF(st_mode),       &scan_int,  0, 4,  8},
        {"st_nlink",    STATOFF(st_nlink),      &scan_int,  0, 4, 10},
        {"st_uid",      STATOFF(st_uid),        &scan_int,  0, 4, 10},
        {"st_gid",      STATOFF(st_gid),        &scan_int,  0, 4, 10},
        {"st_rdev",     STATOFF(st_rdev),       &scan_int,  0, 8, 10},
        {"st_size",     STATOFF(st_size),       &scan_int,  1, 8, 10},
        {"st_blksize",  STATOFF(st_blksize),    &scan_int,  1, 8, 10},
        {"st_blocks",   STATOFF(st_blocks),     &scan_int,  1, 8, 10},
        {"st_atim",     STATOFF(st_atim),       &scan_time, 0, 0,  0},
        {"st_mtim",     STATOFF(st_mtim),       &scan_time, 0, 0,  0},
        {"st_ctim",     STATOFF(st_ctim),       &scan_time, 0, 0,  0},
        {"num_ents",    STATOFF(num_ents),      &scan_int,  0, 4, 10}
    }, *scandescp;

    (void)key;
    (void)datasize;

    for (i = 0; i < ARRAY_SIZE(scandescs); i++) {
        char prompt[32];

        scandescp = &scandescs[i];

        snprintf(prompt, sizeof(prompt), "%s: ", scandescp->nm);
        arg = readline(prompt);
        if (arg == NULL)
            return 2;

        if (arg[strspn(arg, " ")] == '\0') {
            free(arg);
            continue;
        }

        ret = (*(scandescp->scan_field))(arg, s, scandescp->statoff,
                                         scandescp->is_signed,
                                         scandescp->width, scandescp->base);

        free(arg);

        if (ret != 0)
            return ret;
    }

    return 0;
}

#undef STATOFF

static int
set_page(const struct db_key *key, void **data, size_t *datasize)
{
    (void)key;
    (void)data;
    (void)datasize;

    return 0;
}

static int
set_xattr(const struct db_key *key, void **data, size_t *datasize)
{
    (void)key;
    (void)data;
    (void)datasize;

    return 0;
}

static int
set_ulinked_inode(const struct db_key *key, void **data, size_t *datasize)
{
    (void)key;
    (void)data;
    (void)datasize;

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

#define OUTPUT_WIDTH 64
#define NUM_ROWS ((FREE_INO_RANGE_SZ + OUTPUT_WIDTH - 1) / OUTPUT_WIDTH)

static void
disp_free_ino_full(FILE *f, const struct db_key *key, const void *data,
                   size_t datasize)
{
    int i;
    struct db_obj_free_ino *freeino = (struct db_obj_free_ino *)data;

    disp_free_ino(f, key, data, datasize);
    fputc('\n', f);

    for (i = 0;; i++) {
        if (i == FREE_INO_RANGE_SZ) {
            fputc('\n', f);
            break;
        }
        if ((i > 0) && (i % OUTPUT_WIDTH == 0))
            fputc('\n', f);
        fputc(used_ino_get(freeino->used_ino, key->ino, key->ino + i)
              ? '1' : '0',
              f);
    }

    fprintf(f, "Last: %s", (freeino->flags & FREE_INO_LAST_USED) ? "1" : "0");
}

#undef OUTPUT_WIDTH
#undef NUM_ROWS

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
used_ino_get(uint64_t *used_ino, uint32_t base, uint32_t ino)
{
    int idx, wordidx;
    uint64_t mask;

    idx = ino - base;
    wordidx = idx / NBWD;
    mask = 1ull << (idx % NBWD);

    return !!(used_ino[wordidx] & mask);
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
                                   &disp_free_ino_full}
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
        int                 (*set_data)(const struct db_key *, void **,
                                        size_t *);
    } typemap[] = {
        [TYPE_HEADER]           = {"TYPE_HEADER",           OBJSZ(header),
                                   NULL,
                                   &set_header},
        [TYPE_DIRENT]           = {"TYPE_DIRENT",           OBJSZ(dirent),
                                   &get_key_ino_name,
                                   &set_dirent},
        [TYPE_STAT]             = {"TYPE_STAT",             OBJSZ(stat),
                                   &get_key_ino,
                                   &set_stat},
        [TYPE_PAGE]             = {"TYPE_PAGE",             0,
                                   &get_key_ino_pgno,
                                   &set_page},
        [TYPE_XATTR]            = {"TYPE_XATTR",            0,
                                   &get_key_ino_name,
                                   &set_xattr},
        [TYPE_ULINKED_INODE]    = {"TYPE_ULINKED_INODE",    0,
                                   &get_key_ino,
                                   &set_ulinked_inode},
        [TYPE_FREE_INO]         = {"TYPE_FREE_INO",         OBJSZ(free_ino),
                                   &get_key_ino,
                                   &set_free_ino}
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
    if (typep->set_data == NULL)
        goto type_err;

    if (typep->get_args != NULL) {
        res = (*(typep->get_args))(&k);
        if (res != 0)
            return res;
    }
    k.type = type;

    if (typep->datasize == 0) {
        d = NULL;
        datasize = 0;
    } else {
        memset(&data, 0, sizeof(data));
        d = &data;
        datasize = typep->datasize;
    }

    res = (*(typep->set_data))(&k, &d, &datasize);
    if (res != 0)
        goto end;

    res = db_hl_trans_new(dbh);
    if (res != 0)
        goto insert_err;

    res = db_hl_insert(dbh, &k, d, datasize);
    if (res != 0) {
        if (res == -EADDRNOTAVAIL)
            res = -EIO;
        goto insert_err;
    }

    res = db_hl_sync(dbh);
    if (res != 0) {
        db_hl_trans_abort(dbh);
        goto insert_err;
    }

end:
    if (typep->datasize == 0)
        free(d);
    return res;

insert_err:
    if (typep->datasize == 0)
        free(d);
    error(0, -res, "Error insert");
    return res;

type_err:
    error(0, 0, "Invalid object type %d", type);
    return 2;
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
    char *arg;
    enum db_obj_type type;
    int ret;
    size_t i;
    struct db_key k;

    static const struct {
        const char          *nm;
        int                 (*get_args)(struct db_key *);
    } typemap[] = {
        [TYPE_HEADER]           = {"TYPE_HEADER",           &confirm_del_hdr},
        [TYPE_DIRENT]           = {"TYPE_DIRENT",           &get_key_ino_name},
        [TYPE_STAT]             = {"TYPE_STAT",             &get_key_ino},
        [TYPE_PAGE]             = {"TYPE_PAGE",             &get_key_ino_pgno},
        [TYPE_XATTR]            = {"TYPE_XATTR",            &get_key_ino_name},
        [TYPE_ULINKED_INODE]    = {"TYPE_ULINKED_INODE",    &get_key_ino},
        [TYPE_FREE_INO]         = {"TYPE_FREE_INO",         &get_key_ino}
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
    if (typep->get_args == NULL)
        goto type_err;

    if (typep->get_args != NULL) {
        ret = (*(typep->get_args))(&k);
        if (ret != 0)
            return ret;
    }
    k.type = type;

    ret = db_hl_trans_new(dbh);
    if (ret != 0)
        goto delete_err;

    ret = db_hl_delete(dbh, &k);
    if (ret != 0) {
        if (ret != -EADDRNOTAVAIL)
            goto delete_err;
        return 2;
    }

    ret = db_hl_sync(dbh);
    if (ret != 0) {
        db_hl_trans_abort(dbh);
        goto delete_err;
    }

    return 0;

delete_err:
    error(0, -ret, "Error deleting");
    return ret;

type_err:
    error(0, 0, "Invalid object type %d", type);
    return 2;
}

static int
cmd_update(struct dbh *dbh)
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
        int                 (*set_data)(const struct db_key *, void **,
                                        size_t *);
    } typemap[] = {
        [TYPE_HEADER]           = {"TYPE_HEADER",           OBJSZ(header),
                                   NULL,
                                   &set_header},
        [TYPE_DIRENT]           = {"TYPE_DIRENT",           OBJSZ(dirent),
                                   &get_key_ino_name,
                                   &set_dirent},
        [TYPE_STAT]             = {"TYPE_STAT",             OBJSZ(stat),
                                   &get_key_ino,
                                   &set_stat},
        [TYPE_PAGE]             = {"TYPE_PAGE",             0,
                                   &get_key_ino_pgno,
                                   &set_page},
        [TYPE_XATTR]            = {"TYPE_XATTR",            0,
                                   &get_key_ino_name,
                                   &set_xattr},
        [TYPE_ULINKED_INODE]    = {"TYPE_ULINKED_INODE",    0,
                                   &get_key_ino,
                                   &set_ulinked_inode},
        [TYPE_FREE_INO]         = {"TYPE_FREE_INO",         OBJSZ(free_ino),
                                   &get_key_ino,
                                   &set_free_ino}
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
    if (typep->set_data == NULL)
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

    res = (*(typep->set_data))(&k, &d, &datasize);
    if (res != 0)
        goto end;

    res = db_hl_trans_new(dbh);
    if (res != 0)
        goto replace_err;

    res = db_hl_replace(dbh, &k, d, datasize);
    if (res != 0) {
        if (res == -EADDRNOTAVAIL)
            res = -EIO;
        goto replace_err;
    }

    res = db_hl_sync(dbh);
    if (res != 0) {
        db_hl_trans_abort(dbh);
        goto replace_err;
    }

end:
    if (typep->datasize == 0)
        free(d);
    return res;

lookup_err:
    if (res == 0)
        res = 2;
    else
        error(0, -res, "Error looking up");
    return res;

replace_err:
    if (typep->datasize == 0)
        free(d);
    error(0, -res, "Error replacing");
    return res;

type_err:
    error(0, 0, "Invalid object type %d", type);
    return 2;
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
