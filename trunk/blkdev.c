/*
 * blkdev.c
 */

#include "config.h"

#include "blkdev.h"
#include "util.h"

#ifdef __APPLE__
#include "common.h"
#else
#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT
#endif

#include <io_ext.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/file.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_LINUX_MAGIC_H
#include <sys/vfs.h>
#endif

#define BCTX_FD(bctx, n) ((bctx)->fd[n])

#define DFD(bctx) BCTX_FD(bctx, 0)
#define FD(bctx) BCTX_FD(bctx, 1)
#define JFD(bctx) BCTX_FD(bctx, 2)

struct blkdev_ctx {
    int     fd[3];
    off_t   off;
    off_t   joff;
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
    int (*msync)(void *ctx, void *addr, size_t length, int flags);
    int (*mprotect)(void *ctx, void *addr, size_t len, int prot);
    int (*fstat)(void *ctx, int fd, struct stat *s);
    size_t (*pread)(void *ctx, int fd, void *buf, size_t count, off_t offset,
                    size_t maxread, const struct interrupt_data *intdata);
    size_t (*pwrite)(void *ctx, int fd, const void *buf, size_t count,
                     off_t offset, size_t maxwrite,
                     const struct interrupt_data *intdata);
    int (*ftruncate)(void *ctx, int fd, off_t length);
    int (*falloc)(void *ctx, int fd, off_t offset, off_t len);
    int (*fsync)(void *ctx, int fd, const struct interrupt_data *intdata);
    int (*fdatasync)(void *ctx, int fd, const struct interrupt_data *intdata);
    int (*flock)(void *ctx, int fd, int operation);
    int (*fcntl_setfl)(void *ctx, int fd, int flags);
#ifdef HAVE_LINUX_MAGIC_H
    int (*fstatfs)(void *ctx, int fd, struct statfs *buf);
#endif
};

typedef ssize_t (*io_fn_t)(int, void *, size_t, off_t,
                           const struct interrupt_data *);

static int fs_blkdev_openfs(void **ctx, void *args);
static int fs_blkdev_closefs(void *ctx);
static int fs_blkdev_openat(void *ctx, int dfd, const char *pathname, int flags,
                            va_list ap);
static int fs_blkdev_close(void *ctx, int fd);
static void *fs_blkdev_mmap(void *ctx, void *addr, size_t length, int prot,
                            int flags, int fd, off_t offset);
static int fs_blkdev_munmap(void *ctx, void *addr, size_t length);
static int fs_blkdev_msync(void *ctx, void *addr, size_t length, int flags);
static int fs_blkdev_mprotect(void *ctx, void *addr, size_t len, int prot);
static int fs_blkdev_fstat(void *ctx, int fd, struct stat *s);
static size_t fs_blkdev_pread(void *ctx, int fd, void *buf, size_t count,
                              off_t offset, size_t maxread,
                              const struct interrupt_data *intdata);
static size_t fs_blkdev_pwrite(void *ctx, int fd, const void *buf, size_t count,
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
#ifdef HAVE_LINUX_MAGIC_H
static int fs_blkdev_fstatfs(void *ctx, int fd, struct statfs *buf);
#endif

#define JOURNAL_FILE_SUFFIX "_journal"

#if defined(HAVE_LINUX_MAGIC_H) && !defined(NFS_SUPER_MAGIC)
#define NFS_SUPER_MAGIC 1
#endif

const struct fs_ops fs_blkdev_ops = {
    .openfs         = &fs_blkdev_openfs,
    .closefs        = &fs_blkdev_closefs,
    .openat         = &fs_blkdev_openat,
    .close          = &fs_blkdev_close,
    .mmap           = &fs_blkdev_mmap,
    .munmap         = &fs_blkdev_munmap,
    .msync          = &fs_blkdev_msync,
    .mprotect       = &fs_blkdev_mprotect,
    .fstat          = &fs_blkdev_fstat,
    .pread          = &fs_blkdev_pread,
    .pwrite         = &fs_blkdev_pwrite,
    .ftruncate      = &fs_blkdev_ftruncate,
    .falloc         = &fs_blkdev_falloc,
    .fsync          = &fs_blkdev_fsync,
    .fdatasync      = &fs_blkdev_fdatasync,
    .flock          = &fs_blkdev_flock,
    .fcntl_setfl    = &fs_blkdev_fcntl_setfl,
#ifdef HAVE_LINUX_MAGIC_H
    .fstatfs        = &fs_blkdev_fstatfs
#endif
};

static int err_to_errno(int);

static int interrupt_recv(const struct interrupt_data *);

static size_t do_io(io_fn_t, int, void *, size_t, off_t, size_t,
                    const struct interrupt_data *);

static size_t do_ppread(int, void *, size_t, off_t, size_t,
                        const struct interrupt_data *);
static size_t do_ppwrite(int, const void *, size_t, off_t, size_t,
                         const struct interrupt_data *);
#ifndef __APPLE__
static int do_pfsync(int, const struct interrupt_data *);
#ifdef HAVE_FDATASYNC
static int do_pfdatasync(int, const struct interrupt_data *);
#endif
#endif

/*static int falloc(int, off_t, off_t);
*/
static int
err_to_errno(int err)
{
    errno = err;
    return -1;
}

static int
interrupt_recv(const struct interrupt_data *intdata)
{
    if ((intdata != NULL) && (intdata->interrupted != NULL)
        && (*(intdata->interrupted))()) {
        errno = EINTR;
        return 1;
    }

    return 0;
}

static size_t
do_io(io_fn_t fn, int fd, void *buf, size_t len, off_t offset, size_t maxlen,
      const struct interrupt_data *intdata)
{
    size_t num_processed;
    ssize_t ret;

    if (maxlen == 0)
        maxlen = ~((size_t)0);

    for (num_processed = 0; num_processed < len; num_processed += ret) {
        size_t length = MIN(len - num_processed, maxlen);

        if (interrupt_recv(intdata))
            break;

        errno = 0;
        ret = (*fn)(fd, (char *)buf + num_processed, length,
                    offset + num_processed, intdata);
        if (ret <= 0)
            break;
    }

    return num_processed;
}

static size_t
do_ppread(int fd, void *buf, size_t len, off_t offset, size_t maxread,
          const struct interrupt_data *intdata)
{
    return do_io(&ppread, fd, buf, len, offset, maxread, intdata);
}

static size_t
do_ppwrite(int fd, const void *buf, size_t len, off_t offset, size_t maxwrite,
           const struct interrupt_data *intdata)
{
    return do_io((io_fn_t)&ppwrite, fd, (void *)buf, len, offset, maxwrite,
                 intdata);
}

#ifndef __APPLE__
static int
do_pfsync(int fd, const struct interrupt_data *intdata)
{
    return interrupt_recv(intdata) ? -1 : pfsync(fd, intdata);
}

#ifdef HAVE_FDATASYNC
static int
do_pfdatasync(int fd, const struct interrupt_data *intdata)
{
    return interrupt_recv(intdata) ? -1 : pfdatasync(fd, intdata);
}

#endif

#endif

#if 0
/*
 * NOTE: Due to lack of atomicity, falloc() should not be called while
 * concurrent updates to the specified file's size or allocated blocks are being
 * performed on OS X
 */
static int
falloc(int fd, off_t offset, off_t len)
{
#if defined(HAVE_POSIX_FALLOCATE)
    return posix_fallocate(fd, offset, len);
#elif defined(__APPLE__)
    off_t curalloc;
    struct stat s;

    if (offset != 0) /* see F_PREALLOCATE comment below */
        return ENOTSUP;
    if (INT64_MAX - offset < len)
        return EFBIG;

    if (fstat(fd, &s) == -1)
        return ERRNO;
    curalloc = s.st_blocks * 512;

    if (len > curalloc) {
        fstore_t stinfo;

        /*
         * F_PREALLOCATE sets the size in bytes of a file's preallocated block
         * pool on APFS (with decreases in size disallowed), while it increases
         * the size of the pool by the given number of bytes on HFS+. It is not
         * known whether space for holes in a file (which must reside in the
         * range [0, s.st_size)) can be allocated from the file's preallocated
         * block pool. It is not possible to reserve preallocated blocks for an
         * arbitrary range of bytes.
         */

        stinfo.fst_flags = F_ALLOCATEALL;
        stinfo.fst_posmode = F_PEOFPOSMODE;
        stinfo.fst_offset = 0;
        /*
         * stinfo.fst_length should be set to the correct preallocated component
         * of len. If the file has no holes, this is len - s.st_size. However,
         * if the file has holes, this component cannot be accurately determined
         * without a scan of the entire file. Thus, len is used below, ensuring
         * that stinfo.fst_length is greater than or equal to the correct
         * preallocated component. This will allocate more than the requested
         * amount of space if the file has no holes.
         */
        stinfo.fst_length = len;

        if (fcntl(fd, F_PREALLOCATE, &stinfo) == -1)
            return ERRNO;
    }

    /* set file size to offset + len, as with posix_fallocate() */
    len += offset;
    if ((s.st_size < len) && (ftruncate(fd, len) == -1))
        return ERRNO;

    return 0;
#else
    (void)fd;
    (void)offset;
    (void)len;

    return ENOSYS;
#endif
}

#endif

static int
fs_blkdev_openfs(void **ctx, void *args)
{
    size_t i;
    struct blkdev_ctx *ret;

    (void)args;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    for (i = 0; i < ARRAY_SIZE(ret->fd); i++)
        ret->fd[i] = -1;
    ret->off = -1;

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
 * - ".", whose corresponding file should have the directory type
 * - "x_journal" for some prefix "x", whose corresponding file must have the
 *   regular file type
 * - "x" for the same string "x" as the file above, whose corresponding file
 *   must also have the regular file type
 *
 * The function fs_blkdev_openat() should resolve the above pathnames such that
 * each refers to a distinct file or a nonexistent file. In particular, it is
 * important that x_journal and x resolve to different files if they both refer
 * to existing files. If this is not guaranteed, corruption may occur.
 *
 * After a file system is formatted but before it is first mounted, neither the
 * file x_journal nor x should exist. In this case, fs_blkdev_openat() should
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
    int ret;
    struct blkdev_ctx *bctx = (struct blkdev_ctx *)ctx;

    (void)ap;

    if (strcmp(".", pathname) == 0)
        bfd = &DFD(bctx);
    else {
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
    }

    ret = openat(dfd, pathname, flags);
    if (ret != -1)
        *bfd = ret;

    return ret;
}

static int
fs_blkdev_close(void *ctx, int fd)
{
    int ret;
    size_t i;
    struct blkdev_ctx *bctx = (struct blkdev_ctx *)ctx;

    if (fd < 0)
        goto err;
    for (i = 0;; i++) {
        if (i == ARRAY_SIZE(bctx->fd))
            goto err;
        if (fd == bctx->fd[i])
            break;
    }

    ret = close(fd);
    if ((ret != -1) || (errno != EBADF))
        bctx->fd[i] = -1;

    return ret;

err:
    return err_to_errno(EBADF);
}

static void *
fs_blkdev_mmap(void *ctx, void *addr, size_t length, int prot, int flags,
               int fd, off_t offset)
{
    (void)ctx;

    return mmap(addr, length, prot, flags, fd, offset);
}

static int
fs_blkdev_munmap(void *ctx, void *addr, size_t length)
{
    (void)ctx;

    return munmap(addr, length);
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

static int
fs_blkdev_fstat(void *ctx, int fd, struct stat *s)
{
    (void)ctx;

    return err_to_errno(ENOSYS);

    return fstat(fd, s);
}

static size_t
fs_blkdev_pread(void *ctx, int fd, void *buf, size_t count, off_t offset,
                size_t maxread, const struct interrupt_data *intdata)
{
    (void)ctx;

    return err_to_errno(ENOSYS);

    return do_ppread(fd, buf, count, offset, maxread, intdata);
}

static size_t
fs_blkdev_pwrite(void *ctx, int fd, const void *buf, size_t count, off_t offset,
                 size_t maxwrite, const struct interrupt_data *intdata)
{
    (void)ctx;

    return err_to_errno(ENOSYS);

    return do_ppwrite(fd, buf, count, offset, maxwrite, intdata);
}

static int
fs_blkdev_ftruncate(void *ctx, int fd, off_t length)
{
    (void)ctx;

    return err_to_errno(ENOSYS);

    return ftruncate(fd, length);
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
    (void)intdata;

#if defined(__APPLE__)
    return fcntl(fd, F_FULLFSYNC);
#else
    return do_pfsync(fd, intdata);
#endif
}

static int
fs_blkdev_fdatasync(void *ctx, int fd, const struct interrupt_data *intdata)
{
    (void)ctx;
    (void)intdata;

#if defined(__APPLE__)
    return fcntl(fd, F_FULLFSYNC);
#elif !defined(HAVE_FDATASYNC)
    return do_pfsync(fd, intdata);
#else
    return do_pfdatasync(fd, intdata);
#endif
}

static int
fs_blkdev_flock(void *ctx, int fd, int operation)
{
    (void)ctx;

    return flock(fd, operation);
}

static int
fs_blkdev_fcntl_setfl(void *ctx, int fd, int flags)
{
    (void)ctx;

    return fcntl(fd, F_SETFL, flags);
}

#ifdef HAVE_LINUX_MAGIC_H
/*
 * Currently, this function is only required to set the f_type field of the
 * statfs structure *buf to a value other than NFS_SUPER_MAGIC, if this macro is
 * defined in linux/magic.h.
 */
static int
fs_blkdev_fstatfs(void *ctx, int fd, struct statfs *buf)
{
    (void)ctx;
    (void)fd;

    memset(buf, 0, sizeof(*buf));
    /* Return f_type value other than NFS_SUPER_MAGIC */
    buf->f_type = NFS_SUPER_MAGIC - 1;

    return 0;
}

#endif

/* vi: set expandtab sw=4 ts=4: */
