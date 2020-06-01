/*
 * util.c
 */

#include "config.h"

#include "util.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <sys/param.h>
#include <sys/time.h>

#define ASSURE_ERRNO_SET(ret, expr) \
    do { \
        errno = 0; \
        (ret) = (expr); \
        if (((ret) == NULL) && (errno == 0)) \
            errno = ENOMEM; \
    } while (0)

void *
do_malloc(size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, malloc(size));
    return ret;
}

void *
do_calloc(size_t nmemb, size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, calloc(nmemb, size));
    return ret;
}

void *
do_realloc(void *ptr, size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, realloc(ptr, size));
    return ret;
}

/*
 * Average number of loop iterations for log_2_pow2(), assuming a uniform
 * frequency of inputs constrained to any power of 2
 *
 * Linear search algorithm
 * =======================
 *
 * avg_iterations = sum(1, number_of_bits) / number_of_bits
 *                = 32.5
 *
 * Binary search algorithm
 * =======================
 *
 * 4-bit case:
 * -----------
 *
 * Binary search path lengths:
 * 1     ival = 2, res = 2
 * 2 2   ival = 1, res = 1, 3
 *     0 (input = 1)
 *
 * avg_iterations = (1 + 2 + 2) / 4 = 1.25
 *
 * 64-bit case:
 * ------------
 *
 * Binary search path lengths:
 * 1 *  1 ival = 32
 * 2 *  2 ival = 16
 * 3 *  4 ival =  8
 * 4 *  8 ival =  4
 * 5 * 16 ival =  2
 * 6 * 32 ival =  1
 * 0      (input = 1)
 *
 * avg_iterations =
 * (1 + 2 + 4 + 8 + 16 + 32 = (64 - 1) - (1 - 1)
 *      2 + 4 + 8 + 16 + 32 = (64 - 1) - (2 - 1)
 *          4 + 8 + 16 + 32 = (64 - 1) - (4 - 1)
 *              8 + 16 + 32 = (64 - 1) - (8 - 1)
 *                  16 + 32 = (64 - 1) - (16 - 1)
 *                       32 = (64 - 1) - (32 - 1)
 *  -----------------------   -----------------------------
 *                            6 * (64 - 1) - ((64 - 1) - 6)
 *                            6 * (64 - 1) - (64 - 1) + 6
 *                            (6 - 1) * (64 - 1) + 6
 *                            321
 * ) / 64 = 5.015625
 *
 * avg_iterations = ((n - 1) * (2^n - 1) + n) / (2^n)
 *                  where n = log_2(number_of_bits)
 *                  and number_of_bits is a power of 2
 *                = 5.015625
 */

uint32_t
log_2_pow2(uint64_t n)
{
    uint32_t ival, res;

    assert(n != 0);

    if (n == 1)
        return 0;

    res = ival = 32;
    for (;;) {
        uint64_t tmp = n >> res;

        if (tmp == 1)
            break;

        ival /= 2;
        if (tmp > 1)
            res += ival;
        else
            res -= ival;
    }

    return res;
}

int
gettime(clockid_t clk_id, struct timespec *tm)
{
#ifdef HAVE_CLOCK_GETTIME
    return (clock_gettime(clk_id, tm) == -1) ? -errno : 0;
#else
    struct timeval tv;

    if (clk_id != CLOCK_REALTIME)
        return -ENOTSUP;

    if (gettimeofday(&tv, NULL) == -1)
        return -errno;

    tm->tv_sec = tv.tv_sec;
    tm->tv_nsec = tv.tv_usec * 1000;
    return 0;
#endif
}

/* vi: set expandtab sw=4 ts=4: */
