/*
 * mkfs.simplefs.c
 */

#include "common.h"
#include "util.h"

#include <strings_ext.h>

#include <readline/history.h>
#include <readline/readline.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#define MAGIC 0x53464d53

struct disk_header {
    uint32_t    magic;
    uint64_t    off;        /* data area offset */
    uint64_t    joff;       /* journal offset */
    uint64_t    blkdevsz;   /* total device size */
    uint8_t     padding[4096 - sizeof(uint32_t) - 3 * sizeof(uint64_t)];
} __attribute__((packed));

static void print_usage(const char *);

static int parse_cmdline(int, char **, int *, const char **);

static int query(const char *);

static int init_header(int);
static int zero_data_and_journal_areas(int);

static int format_device(const char *, int);

static void
print_usage(const char *prognm)
{
    printf("Usage: %s [options]\n"
           "\n"
           "    -f Force formatting to start\n"
           "    -h Output help\n",
           prognm);
}

static int
parse_cmdline(int argc, char **argv, int *force, const char **dev)
{
    for (;;) {
        int opt = getopt(argc, argv, "fh");

        if (opt == -1)
            break;

        switch (opt) {
        case 'f':
            *force = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return -2;
        default:
            return -1;
        }
    }

    if (optind != argc - 1) {
        fprintf(stderr, "%s\n",
                (optind == argc)
                ? "Must specify device" : "Unrecognized arguments");
        return -1;
    }
    *dev = argv[optind];

    return 0;
}

static int
query(const char *prompt)
{
    char *input;
    int res;

    fputs(prompt, stdout);
    fflush(stdout);

    if (tcflush(STDIN_FILENO, TCIFLUSH) == -1)
        return -1;

    input = readline(NULL);
    if (input == NULL)
        return -1;

    res = ((input[0] == 'y') || (input[0] == 'Y'));

    free(input);

    return res;
}

static int
init_header(int fd)
{
    struct disk_header hdr;

    omemset(&hdr, 0);
    hdr.magic = MAGIC;

    return (do_ppwrite(fd, &hdr, sizeof(hdr), 0, 4096, NULL) == sizeof(hdr))
           ? 0 : -EIO;
}

#define IO_SIZE (2 * 1024 * 1024)

static int
zero_data_and_journal_areas(int fd)
{
    int err = 0;
    off_t totwritten;

    totwritten = sizeof(struct disk_header);
    for (;;) {
        size_t numwritten;
        ssize_t res;
        static const char zerobuf[IO_SIZE];

        for (numwritten = 0; numwritten < IO_SIZE; numwritten += res) {
            res = do_ppwrite(fd, zerobuf, IO_SIZE - numwritten,
                             totwritten + numwritten, IO_SIZE, NULL);
            if (res > 0)
                continue;
            if ((res != 0) && (errno != ENOSPC))
                err = MINUS_ERRNO;
            else
                totwritten += numwritten;
            goto end;
        }

        totwritten += IO_SIZE;

        fprintf(stderr, "\rWrote %19" PRIi64 " bytes", totwritten);
    }

end:
    if (totwritten > (off_t)sizeof(struct disk_header))
        fprintf(stderr, "\rWrote %19" PRIi64 " bytes\n", totwritten);
    return err;
}

#undef IO_SIZE

static int
format_device(const char *dev, int force)
{
    const char *errmsg = "Error writing to %s";
    int fd;
    int res = 0;
    struct stat s;

    fd = open(dev, O_WRONLY);
    if (fd == -1) {
        errmsg = "Error opening %s";
        goto err2;
    }

    if (fstat(fd, &s) == -1) {
        errmsg = "Error getting status of %s";
        goto err2;
    }
    if (!S_ISBLK(s.st_mode)) {
        res = -ENODEV;
        errmsg = "%s is not a block device";
        goto err1;
    }

    if (force)
        fprintf(stderr, "Formatting of %s forced using \"-f\" option\n", dev);
    else {
        fprintf(stderr, "Warning: Device %s will be completely overwritten.\n"
                        "         All data on %s will be destroyed.\n"
                        "         It is advised to mount the file system\n"
                        "         on %s (if any), confirm the intended data\n"
                        "         will be overwritten, and unmount it before\n"
                        "         proceeding.\n",
                dev, dev, dev);
        res = query("Please confirm if formatting should proceed (y/n): ");
        if (res != 1) {
            close(fd);
            fprintf(stderr, "Device %s not written\n", dev);
            return (res == 0) ? -ECANCELED : -ENOMEM;
        }
    }

    res = init_header(fd);
    if (res != 0)
        goto err1;

    res = zero_data_and_journal_areas(fd);
    if (res != 0)
        goto err1;

    if (fsync(fd) == -1)
        goto err2;

    if (close(fd) == -1) {
        fd = -1;
        errmsg = "Error closing %s";
        goto err2;
    }

    fprintf(stderr, "Device %s formatted successfully\n", dev);

    return 0;

err2:
    res = MINUS_ERRNO;
err1:
    if (fd != -1)
        close(fd);
    error(0, -res, errmsg, dev);
    return res;
}

int
main(int argc, char **argv)
{
    const char *dev = NULL;
    int force = 0;
    int ret;

    ret = parse_cmdline(argc, argv, &force, &dev);
    if (ret != 0)
        return (ret == -2) ? EXIT_SUCCESS : EXIT_FAILURE;

    return (format_device(dev, force) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
