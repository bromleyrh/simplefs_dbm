/*
 * blkdev.c
 */

#include "config.h"

#include "blkdev.h"
#include "common.h"
#include "obj.h"
#include "sys_dep.h"
#include "util.h"

#ifndef SYS_DEP_BLK_GET_SIZE
#error "Support for platform not yet implemented"
#endif

#include <io_ext.h>
#include <packing.h>
#include <strings_ext.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

/* The disk header size must be a multiple of 4096 */
STATIC_ASSERT(sizeof(struct disk_header) == 4096);

#define FLOCK_SH 1
#define FLOCK_EX 2
#define FLOCK_NB 4
#define FLOCK_UN 8

#define BLKDEV_OPEN(bctx) (unpack_u64(disk_header, &(bctx)->hdr, blkdevsz) > 0)

#define BCTX_FD(bctx, n) ((bctx)->fd[n])

#define DFD(bctx) BCTX_FD(bctx, 0)
#define FD(bctx) BCTX_FD(bctx, 1)
#define JFD(bctx) BCTX_FD(bctx, 2)

struct blkdev_ctx {
    struct blkdev_args  *args;
    struct disk_header  hdr;
    int                 fd[3];
    void                *mmap_addr;
    int                 lkfd;
    int                 lk;
    int                 jlk;
    int                 init;
    int                 jinit;
};

typedef struct {
    int64_t val[2];
} fs_id_t;

struct fs_stat {
    uint64_t    f_type;     /* type of file system */
    uint64_t    f_blocks;   /* total data blocks in file system */
    uint64_t    f_bfree;    /* free blocks in file system */
    uint64_t    f_files;    /* total file nodes in file system */
    fs_id_t     f_fsid;     /* file system ID */
    uint64_t    f_flags;    /* mount flags of file system */
};

struct fs_ops {
    int (*openfs)(void **ctx, void *args);
    int (*closefs)(void *ctx);
    int (*openat)(void *ctx, int dfd, const char *pathname, int flags,
                  va_list ap);
    int (*close)(void *ctx, int fd);
    void *(*mmap)(void *ctx, void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
    int (*munmap)(void *ctx, void *addr, size_t length);
    int (*mmap_validate_range)(void *ctx, void *addr, size_t length);
    int (*msync)(void *ctx, void *addr, size_t length, int flags);
    int (*mprotect)(void *ctx, void *addr, size_t len, int prot);
    int (*fstat)(void *ctx, int fd, struct stat *s);
    size_t (*pread)(void *ctx, int fd, void *buf, size_t count, off_t offset,
                    size_t maxread, const struct interrupt_data *intdata);
    size_t (*pwrite)(void *ctx, int fd, void *buf, size_t count, off_t offset,
                     size_t maxwrite, const struct interrupt_data *intdata);
    int (*ftruncate)(void *ctx, int fd, off_t length);
    int (*falloc)(void *ctx, int fd, off_t offset, off_t len);
    int (*fsync)(void *ctx, int fd, const struct interrupt_data *intdata);
    int (*fdatasync)(void *ctx, int fd, const struct interrupt_data *intdata);
    int (*flock)(void *ctx, int fd, int operation);
    int (*fcntl_setfl)(void *ctx, int fd, int flags);
    int (*fstatfs)(void *ctx, int fd, struct fs_stat *buf);
};

static int fs_blkdev_openfs(void **ctx, void *args);
static int fs_blkdev_closefs(void *ctx);
static int fs_blkdev_openat(void *ctx, int dfd, const char *pathname, int flags,
                            va_list ap);
static int fs_blkdev_close(void *ctx, int fd);
static void *fs_blkdev_mmap(void *ctx, void *addr, size_t length, int prot,
                            int flags, int fd, off_t offset);
static int fs_blkdev_munmap(void *ctx, void *addr, size_t length);
static int fs_blkdev_mmap_validate_range(void *ctx, void *addr, size_t length);
static int fs_blkdev_msync(void *ctx, void *addr, size_t length, int flags);
static int fs_blkdev_mprotect(void *ctx, void *addr, size_t len, int prot);
static int fs_blkdev_fstat(void *ctx, int fd, struct stat *s);
static size_t fs_blkdev_pread(void *ctx, int fd, void *buf, size_t count,
                              off_t offset, size_t maxread,
                              const struct interrupt_data *intdata);
static size_t fs_blkdev_pwrite(void *ctx, int fd, void *buf, size_t count,
                               off_t offset, size_t maxwrite,
                               const struct interrupt_data *intdata);
static int fs_blkdev_ftruncate(void *ctx, int fd, off_t length);
static int fs_blkdev_falloc(void *ctx, int fd, off_t offset, off_t len);
static int fs_blkdev_fsync(void *ctx, int fd,
                           const struct interrupt_data *intdata);
static int fs_blkdev_fdatasync(void *ctx, int fd,
                               const struct interrupt_data *intdata);
static int fs_blkdev_flock(void *ctx, int fd, int operation);
static int fs_blkdev_fcntl_setfl(void *ctx, int fd, int flags);
static int fs_blkdev_fstatfs(void *ctx, int fd, struct fs_stat *buf);

#define JOURNAL_FILE_SUFFIX "_journal"

/* These sizes must be a multiple of 4096 */
#define DATA_MIN_SIZE (2 * 1024 * 1024)
#define DATA_SIZE(bctx) \
    (unpack_u64(disk_header, &(bctx)->hdr, joff) - sizeof(struct disk_header))
#define JOURNAL_SIZE (256 * 1024 * 1024)

#define BLKDEV_MIN_SIZE \
    (sizeof(struct disk_header) + DATA_MIN_SIZE + JOURNAL_SIZE)

#if defined(HAVE_LINUX_MAGIC_H) && !defined(NFS_SUPER_MAGIC)
#define NFS_SUPER_MAGIC 1
#endif

#define IO_SIZE 4096

const struct fs_ops fs_blkdev_ops = {
    .openfs                 = &fs_blkdev_openfs,
    .closefs                = &fs_blkdev_closefs,
    .openat                 = &fs_blkdev_openat,
    .close                  = &fs_blkdev_close,
    .mmap                   = &fs_blkdev_mmap,
    .munmap                 = &fs_blkdev_munmap,
    .mmap_validate_range    = &fs_blkdev_mmap_validate_range,
    .msync                  = &fs_blkdev_msync,
    .mprotect               = &fs_blkdev_mprotect,
    .fstat                  = &fs_blkdev_fstat,
    .pread                  = &fs_blkdev_pread,
    .pwrite                 = &fs_blkdev_pwrite,
    .ftruncate              = &fs_blkdev_ftruncate,
    .falloc                 = &fs_blkdev_falloc,
    .fsync                  = &fs_blkdev_fsync,
    .fdatasync              = &fs_blkdev_fdatasync,
    .flock                  = &fs_blkdev_flock,
    .fcntl_setfl            = &fs_blkdev_fcntl_setfl,
    .fstatfs                = &fs_blkdev_fstatfs
};

static int err_to_errno(int);
static size_t err_to_errno_sz(int);
static void *err_to_errno_p(int);

static int blkdev_flags(int);
static int get_blkdev_size(int, uint64_t *);

static void init_header(struct disk_header *, uint64_t);
static int read_header(int, struct disk_header *);
static int write_header(int, const struct disk_header *);

static int open_blkdev(int, int, int, int *, struct blkdev_ctx *);

static int check_fd_regular(int, struct blkdev_ctx *);

static size_t do_blkdev_io(struct blkdev_ctx *, int, void *, size_t, off_t,
                           size_t, const struct interrupt_data *, int);

static int xlat_lock_op(int);

static int _flock(int, int, int);

static int
err_to_errno(int err)
{
    errno = err;
    return -1;
}

static size_t
err_to_errno_sz(int err)
{
    errno = err;
    return 0;
}

static void *
err_to_errno_p(int err)
{
    errno = err;
    return NULL;
}

static int
blkdev_flags(int flags)
{
    return flags & ~(O_CREAT | O_EXCL);
}

static int
get_blkdev_size(int fd, uint64_t *sz)
{
    return blk_get_size(fd, sz) == -1 ? MINUS_ERRNO : 0;
}

static void
init_header(struct disk_header *hdr, uint64_t blkdevsz)
{
    pack_u64(disk_header, hdr, off, sizeof(*hdr));
    pack_u64(disk_header, hdr, joff, (blkdevsz - JOURNAL_SIZE) / 4096 * 4096);
    pack_u64(disk_header, hdr, blkdevsz, blkdevsz);
}

static int
read_header(int fd, struct disk_header *hdr)
{
    return do_ppread(fd, hdr, sizeof(*hdr), 0, IO_SIZE, NULL) == sizeof(*hdr)
           ? 0 : -EIO;
}

static int
write_header(int fd, const struct disk_header *hdr)
{
    return do_ppwrite(fd, hdr, sizeof(*hdr), 0, IO_SIZE, NULL) == sizeof(*hdr)
           ? 0 : -EIO;
}

static int
open_blkdev(int fd, int create, int ro, int *initialized,
            struct blkdev_ctx *bctx)
{
    int err;
    uint32_t hdr_magic;
    uint64_t blkdevsz, hdr_blkdevsz;

    err = get_blkdev_size(fd, &blkdevsz);
    if (err)
        return err;
    if (blkdevsz < BLKDEV_MIN_SIZE)
        return -ERANGE;

    err = read_header(fd, &bctx->hdr);
    if (err)
        return err;
    hdr_magic = unpack_u32(disk_header, &bctx->hdr, magic);
    if (hdr_magic != MAGIC) { /* not formatted */
        errmsg("Device not formatted\n");
        return -EILSEQ;
    }
    hdr_blkdevsz = unpack_u64(disk_header, &bctx->hdr, blkdevsz);
    if (hdr_blkdevsz == 0) { /* not initialized */
        if (ro)
            return -EROFS;
        if (!create)
            return -ENOENT;
        init_header(&bctx->hdr, blkdevsz);
        err = write_header(fd, &bctx->hdr);
        if (err)
            return err;
        if (fsync(fd) == -1)
            return MINUS_ERRNO;
        *initialized = 1;
        return 0;
    }
    if (hdr_blkdevsz != blkdevsz) {
        /* device size changed after initialization */
        errmsgf("Device size changed from %" PRIu64 "\n", hdr_blkdevsz);
        return -EILSEQ;
    }

    *initialized = 0;
    return 0;
}

static int
check_fd_regular(int fd, struct blkdev_ctx *bctx)
{
    if (fd != FD(bctx) && fd != JFD(bctx))
        return err_to_errno(fd == DFD(bctx) ? EINVAL : EBADF);

    return 0;
}

static size_t
do_blkdev_io(struct blkdev_ctx *bctx, int fd, void *buf, size_t count,
             off_t offset, size_t maxio, const struct interrupt_data *intdata,
             int direction)
{
    int ret;
    off_t maxreloff, off;

    ret = check_fd_regular(fd, bctx);
    if (ret != 0)
        return ret;
    if (offset < 0)
        return err_to_errno_sz(EINVAL);
    if (count > (uint64_t)(INT64_MAX - offset))
        return err_to_errno_sz(EOVERFLOW);

    if (fd == JFD(bctx)) {
        maxreloff = JOURNAL_SIZE;
        off = unpack_u64(disk_header, &bctx->hdr, joff);
    } else {
        maxreloff = DATA_SIZE(bctx);
        off = unpack_u64(disk_header, &bctx->hdr, off);
    }
    off += offset;

    if (offset + (off_t)count > maxreloff)
        return err_to_errno_sz(ENOSPC);

    return direction == 0
           ? do_ppread(fd, buf, count, off, maxio, intdata)
           : do_ppwrite(fd, buf, count, off, maxio, intdata);
}

static int
xlat_lock_op(int operation)
{
    int fl;
    int i;

    static const struct ent {
        int src;
        int dst;
    } flmap[] = {
        {FLOCK_SH, FILE_LOCK_SH},
        {FLOCK_EX, FILE_LOCK_EX},
        {FLOCK_NB, FILE_LOCK_NB},
        {FLOCK_UN, FILE_LOCK_UN}
    };

    fl = 0;
    for (i = 0; i < (int)ARRAY_SIZE(flmap); i++) {
        const struct ent *ent = &flmap[i];

        if (operation & ent->src)
            fl |= ent->dst;
    }

    return fl;
}

static int
_flock(int fd, int operation, int blkdev)
{
#ifdef HAVE_FCNTL_F_OFD_LOCKS
    int err;

    (void)blkdev;

    err = fcntl_ofd_setlk(fd, xlat_lock_op(operation));
    return err ? err_to_errno(err) : 0;
#else
    int fl;
    int i;

    if (blkdev && operation & FILE_LOCK_SH) {
        if (operation & (FILE_LOCK_EX | FILE_LOCK_UN))
            return err_to_errno(EINVAL);
        operation = FILE_LOCK_EX | (operation & FILE_LOCK_NB);
    }

    fl = xlat_lock_op(operation);

    for (i = 0;; i++) { /* work around Linux kernel race condition */
        if (file_lock(fd, fl) == 0)
            break;
        if (errno != EAGAIN || i == 10)
            return -1;
        sleep(1);
    }

    return 0;
#endif
}

static int
fs_blkdev_openfs(void **ctx, void *args)
{
    size_t i;
    struct blkdev_ctx *ret;

    if (oemalloc(&ret) == NULL)
        return MINUS_ERRNO;

    ret->args = args;

    pack_u64(disk_header, &ret->hdr, blkdevsz, 0);

    for (i = 0; i < ARRAY_SIZE(ret->fd); i++)
        ret->fd[i] = -1;
    ret->mmap_addr = NULL;
    ret->lkfd = -1;
    ret->lk = ret->jlk = 0;
    ret->init = ret->jinit = -1;

    ret->args->hdrlen = sizeof(struct disk_header);
    ret->args->jlen = JOURNAL_SIZE;

    *ctx = ret;
    return 0;
}

static int
fs_blkdev_closefs(void *ctx)
{
    free(ctx);

    return 0;
}

/*
 * This function receives open requests for exactly the following pathnames:
 * - exactly one of "." and "x/" (with the O_DIRECTORY flag set), whose
 *   corresponding file should have the directory type
 * - "y_journal" for some prefix "y", whose corresponding file must have the
 *   regular file type
 * - "y" for the same string "y" as the file above, whose corresponding file
 *   must also have the regular file type
 *
 * The function fs_blkdev_openat() should resolve the above pathnames such that
 * each refers to a distinct file or a nonexistent file. In particular, it is
 * important that y_journal and y resolve to different files if they both refer
 * to existing files. If this is not guaranteed, corruption may occur.
 *
 * After a file system is formatted but before it is first mounted, neither the
 * file y_journal nor y should exist. In this case, fs_blkdev_openat() should
 * return descriptors for these files only if O_CREAT is specified in the flags
 * argument, in which case it should create a new file for each. The results for
 * the case where a file system has not been formatted are undefined.
 *
 * Above, having the type T means that fs_blkdev_fstat() returns the type T in
 * the st_mode field of the status structure for a file descriptor referring to
 * the file. Also, if T is the regular file type, all of the below operations
 * must be supported on a file descriptor referencing the file. Otherwise, T is
 * the directory type, and only the openat, close, and fsync operations need to
 * be supported.
 */
static int
fs_blkdev_openat(void *ctx, int dfd, const char *pathname, int flags,
                 va_list ap)
{
    char buf[PATH_MAX];
    int *bfd;
    int create, ro;
    int dir;
    int *init, initialized;
    int res, ret;
    struct blkdev_ctx *bctx = ctx;
    struct stat s;

    (void)ap;

    if (flags & O_DIRECTORY) {
        bfd = &DFD(bctx);
        dir = 1;
    } else {
        size_t plen, slen;

        slen = strlen(pathname);
        plen = slen - sizeof(JOURNAL_FILE_SUFFIX) + 1;

        if (strcmp(JOURNAL_FILE_SUFFIX, pathname + plen) == 0) {
            if (plen >= sizeof(buf))
                return err_to_errno(ENAMETOOLONG);
            strncpy(buf, pathname, plen);
            buf[plen] = '\0';
            pathname = buf;
            bfd = &JFD(bctx);
        } else
            bfd = &FD(bctx);

        dir = 0;
    }

    ret = openat(dfd, pathname, dir ? flags : blkdev_flags(flags));
    if (ret == -1)
        return -1;

    if (dir)
        goto end;

    if (fstat(ret, &s) == -1) {
        res = MINUS_ERRNO;
        goto err;
    }
    if ((s.st_mode & S_IFMT) != S_IFBLK) {
        res = -ENODEV;
        goto err;
    }

    create = !!(flags & O_CREAT);
    ro = (flags & O_ACCMODE) == O_RDONLY;

    if (!BLKDEV_OPEN(bctx)) {
        res = open_blkdev(ret, create, ro, &initialized, bctx);
        if (res != 0)
            goto err;
        bctx->init = bctx->jinit = !initialized;
    }

    init = bfd == &FD(bctx) ? &bctx->init : &bctx->jinit;
    if (create) {
        if (!*init)
            *init = 1;
        else if (flags & O_EXCL) {
            res = -EEXIST;
            goto err;
        }
    } else if (!*init) {
        res = -ENOENT;
        goto err;
    }

    bctx->args->blkdevsz = unpack_u64(disk_header, &bctx->hdr, blkdevsz);

end:
    *bfd = ret;
    return ret;

err:
    close(ret);
    return err_to_errno(-res);
}

static int
fs_blkdev_close(void *ctx, int fd)
{
    int ret;
    size_t i;
    struct blkdev_ctx *bctx = ctx;

    if (fd < 0)
        goto err;
    for (i = 0;; i++) {
        if (i == ARRAY_SIZE(bctx->fd))
            goto err;
        if (fd == bctx->fd[i])
            break;
    }

    /* If block device is locked through another descriptor fdp and bctx->lkfd
       is being closed (fd == bctx->lkfd and fdp != bctx->lkfd), close fdp
       instead and remap the virtual descriptors by swapping bctx->fd and
       bctx->jfd */
    if (fd == bctx->lkfd) {
        if (bctx->jlk && fd == FD(bctx)) {
            fd = JFD(bctx);
            JFD(bctx) = FD(bctx);
            FD(bctx) = fd;
        } else if (bctx->lk && fd == JFD(bctx)) {
            fd = FD(bctx);
            FD(bctx) = JFD(bctx);
            JFD(bctx) = fd;
        }
    }

    ret = close(fd);
    if (ret != -1 || errno != EBADF) {
        if (fd == FD(bctx))
            bctx->lk = 0;
        else if (fd == JFD(bctx))
            bctx->jlk = 0;
        if (fd == bctx->lkfd)
            bctx->lkfd = -1;
        bctx->fd[i] = -1;
    }

    return ret;

err:
    return err_to_errno(EBADF);
}

/*
 * All memory-mapping functions are only invoked for the file y in the comment
 * for fs_blkdev_openat().
 */

/*
 * This function is only invoked with an offset argument of 0.
 */
static void *
fs_blkdev_mmap(void *ctx, void *addr, size_t length, int prot, int flags,
               int fd, off_t offset)
{
    struct blkdev_ctx *bctx = ctx;
    void *ret;

    if (fd != FD(bctx) || offset != 0)
        return err_to_errno_p(EINVAL);

    ret = mmap(addr, length, prot, flags, fd,
               unpack_u64(disk_header, &bctx->hdr, off) + offset);
    if (ret != NULL)
        bctx->mmap_addr = ret;

    return ret;
}

/*
 * This function is only invoked to unmap the exact range mapped by a previous
 * call to mmap(), or to truncate a previously mapped range.
 */
static int
fs_blkdev_munmap(void *ctx, void *addr, size_t length)
{
    int ret;
    struct blkdev_ctx *bctx = ctx;

    ret = munmap(addr, length);
    if (addr == bctx->mmap_addr && ret != 0)
        bctx->mmap_addr = NULL;

    return ret;
}

/*
 * This function must perform any needed address access checks that would not
 * otherwise necessarily be performed by accessing a byte in the range
 * [addr, addr + length). It may also perform redundant checks to avoid raising
 * an exception.
 */
static int
fs_blkdev_mmap_validate_range(void *ctx, void *addr, size_t length)
{
    struct blkdev_ctx *bctx = ctx;

    if (bctx->mmap_addr == NULL || (char *)addr < (char *)bctx->mmap_addr)
        return err_to_errno(EFAULT);

    if ((char *)addr + length > (char *)bctx->mmap_addr + DATA_SIZE(bctx))
        return err_to_errno(ENOSPC);

    return 0;
}

static int
fs_blkdev_msync(void *ctx, void *addr, size_t length, int flags)
{
    (void)ctx;

    return msync(addr, length, flags);
}

static int
fs_blkdev_mprotect(void *ctx, void *addr, size_t len, int prot)
{
    (void)ctx;

    return mprotect(addr, len, prot);
}

/*
 * This function is only required to set the st_mode, st_rdev, and st_size
 * fields of *s appropriately, and is only required to support regular files.
 * The st_rdev field should be nonzero if the st_size field is undefined for the
 * file, and zero otherwise. If st_size is undefined, it may be set to any
 * value.
 */
static int
fs_blkdev_fstat(void *ctx, int fd, struct stat *s)
{
    int ret;
    struct blkdev_ctx *bctx = ctx;

    ret = check_fd_regular(fd, bctx);
    if (ret != 0)
        return ret;

    omemset(s, 0);
    s->st_mode = S_IFREG;
    s->st_rdev = (dev_t)~0;
    s->st_size = fd == FD(bctx) ? DATA_SIZE(bctx) : JOURNAL_SIZE;

    return 0;
}

static size_t
fs_blkdev_pread(void *ctx, int fd, void *buf, size_t count, off_t offset,
                size_t maxread, const struct interrupt_data *intdata)
{
    struct blkdev_ctx *bctx = ctx;

    return do_blkdev_io(bctx, fd, buf, count, offset, maxread, intdata, 0);
}

static size_t
fs_blkdev_pwrite(void *ctx, int fd, void *buf, size_t count, off_t offset,
                 size_t maxwrite, const struct interrupt_data *intdata)
{
    struct blkdev_ctx *bctx = ctx;

    return do_blkdev_io(bctx, fd, buf, count, offset, maxwrite, intdata, 1);
}

static int
fs_blkdev_ftruncate(void *ctx, int fd, off_t length)
{
    (void)ctx;
    (void)fd;

    return length < 0 ? err_to_errno(EINVAL) : 0;
}

static int
fs_blkdev_falloc(void *ctx, int fd, off_t offset, off_t len)
{
    (void)ctx;
    (void)fd;
    (void)offset;
    (void)len;

    return 0;
}

static int
fs_blkdev_fsync(void *ctx, int fd, const struct interrupt_data *intdata)
{
    (void)ctx;

    return do_pfsync_dev(fd, intdata);
}

static int
fs_blkdev_fdatasync(void *ctx, int fd, const struct interrupt_data *intdata)
{
    (void)ctx;

    return do_pfdatasync_dev(fd, intdata);
}

#define LOCK_OPS (FLOCK_SH | FLOCK_EX | FLOCK_UN)

static int
fs_blkdev_flock(void *ctx, int fd, int operation)
{
    int op;
    struct blkdev_ctx *bctx = ctx;

    if (fd != FD(bctx) && fd != JFD(bctx))
        return _flock(fd, operation, 0);

    if (operation & ~(LOCK_OPS | FLOCK_NB))
        return err_to_errno(EINVAL);

    op = operation & LOCK_OPS;

    if (op == FLOCK_UN) {
        if (bctx->lkfd == -1)
            goto end;
        if ((fd == FD(bctx) && bctx->jlk) || (fd == JFD(bctx) && bctx->lk))
            goto end;
    } else {
        if (op != FLOCK_SH && op != FLOCK_EX)
            return err_to_errno(EINVAL);
        if (bctx->lkfd != -1)
            goto end;
    }

    if (_flock(fd, operation, 1) == -1)
        return -1;
    bctx->lkfd = op == FLOCK_UN ? -1 : fd;

end:
    *(fd == FD(bctx) ? &bctx->lk : &bctx->jlk) = op != FLOCK_UN;
    return 0;
}

#undef LOCK_OPS

static int
fs_blkdev_fcntl_setfl(void *ctx, int fd, int flags)
{
    (void)ctx;

    return fcntl(fd, F_SETFL, flags);
}

/*
 * Currently, this function is only required to set the f_type field of the
 * fs_stat structure *buf to a value other than NFS_SUPER_MAGIC, if this macro
 * is defined in linux/magic.h.
 */
static int
fs_blkdev_fstatfs(void *ctx, int fd, struct fs_stat *buf)
{
    (void)ctx;
    (void)fd;

    omemset(buf, 0);
#ifdef HAVE_LINUX_MAGIC_H
    /* Return f_type value other than NFS_SUPER_MAGIC */
    buf->f_type = ~NFS_SUPER_MAGIC;
#endif

    return 0;
}


/* vi: set expandtab sw=4 ts=4: */
