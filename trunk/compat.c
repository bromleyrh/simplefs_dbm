/*
 * compat.c
 */

#include "back_end.h"
#include "back_end_dbm.h"
#include "compat.h"
#include "obj.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <fuse_lowlevel.h>

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

struct foreach_alloc_ctx {
    FILE        *f;
    uint64_t    tot_sz;
};

typedef int check_init_fn_t(struct back_end *, int, int);
typedef int init_fn_t(struct back_end *, size_t, size_t, int, int);

int used_ino_set(uint64_t *, fuse_ino_t, fuse_ino_t, int);

static void foreach_alloc_cb(uint64_t, int, void *);

static check_init_fn_t check_init_default;
static check_init_fn_t check_init_ro_or_fmtconv;

static init_fn_t init_ver_2_to_3;
static init_fn_t init_ver_3_to_4;
static init_fn_t init_ver_4_to_5;
static init_fn_t init_ver_5_to_6;

static int
check_init_default(struct back_end *be, int ro, int fmtconv)
{
    (void)be;

    if (ro) {
        if (fmtconv)
            fputs("Warning: Ignoring fmtconv mount flag\n", stderr);
        return 0;
    }

    return 1;
}

static int
check_init_ro_or_fmtconv(struct back_end *be, int ro, int fmtconv)
{
    (void)be;

    if (ro) {
        if (fmtconv)
            fputs("Warning: Ignoring fmtconv mount flag\n", stderr);
        return 0;
    }

    return fmtconv ? 1 : -EPROTONOSUPPORT;
}

/*
 * Format v2 to v3 conversion:
 * 1. Add used I-node number entry for each TYPE_STAT object in back end
 * 2. Set FREE_INO_LAST_USED flag for last free I-node number object
 * 3. Set numinodes field in header object
 */
static int
init_ver_2_to_3(struct back_end *be, size_t hdrlen, size_t jlen, int ro,
                int fmtconv)
{
    int end;
    int res;
    struct back_end_iter *iter;
    struct db_key k, sk;
    struct db_obj_free_ino freeino;
    struct db_obj_header hdr;
    uint64_t numinodes, tot_numinodes;

    (void)hdrlen;
    (void)jlen;
    (void)ro;
    (void)fmtconv;

    res = back_end_trans_new(be);
    if (res != 0)
        return res;

    sk.type = TYPE_STAT;
    sk.ino = 0;

    k.type = TYPE_FREE_INO;

    tot_numinodes = 0;
    end = 0;
    for (;;) {
        fuse_ino_t base;
        uint32_t cur_rng;

        res = back_end_iter_new(&iter, be);
        if (res != 0)
            goto err1;

        res = back_end_iter_search(iter, &sk);
        if (res < 0)
            goto err2;

        res = back_end_iter_get(iter, &sk, NULL, NULL);
        if (res != 0)
            goto err2;

        if (sk.type != TYPE_STAT) {
            if (tot_numinodes < 1) {
                res = -EILSEQ;
                goto err2;
            }
            back_end_iter_free(iter);
            break;
        }

        cur_rng = (sk.ino - FUSE_ROOT_ID) / FREE_INO_RANGE_SZ;
        base = sk.ino;
        memset(freeino.used_ino, 0, sizeof(freeino.used_ino));
        for (numinodes = 1;; numinodes++) {
            uint32_t rng;

            assert(numinodes <= FREE_INO_RANGE_SZ);

            fprintf(stderr, "Found I-node %" PRIu64 "\n", (uint64_t)(sk.ino));

            used_ino_set(freeino.used_ino, base, sk.ino, 1);

            res = back_end_iter_next(iter);
            if (res != 0) {
                if (res != -EADDRNOTAVAIL)
                    goto err2;
                end = 1;
                break;
            }

            res = back_end_iter_get(iter, &sk, NULL, NULL);
            if (res != 0)
                goto err2;

            if (sk.type != TYPE_STAT) {
                end = 1;
                break;
            }

            rng = (sk.ino - FUSE_ROOT_ID) / FREE_INO_RANGE_SZ;
            if (rng != cur_rng)
                break;
        }

        back_end_iter_free(iter);

        tot_numinodes += numinodes;

        k.ino = base;

        if (numinodes < FREE_INO_RANGE_SZ) {
            res = back_end_insert(be, &k, &freeino, sizeof(freeino));
            if (res != 0)
                goto err1;
        }

        if (end)
            break;
    }

    freeino.flags = FREE_INO_LAST_USED;

    if (numinodes < FREE_INO_RANGE_SZ)
        res = back_end_replace(be, &k, &freeino, sizeof(freeino));
    else
        res = back_end_insert(be, &k, &freeino, sizeof(freeino));
    if (res != 0)
        goto err1;

    res = back_end_look_up(be, &k, NULL, &hdr, NULL, 0);
    if (res != 1) {
        if (res == 0)
            res = -EILSEQ;
        goto err1;
    }

    k.type = TYPE_HEADER;

    hdr.version = 3;
    hdr.numinodes = tot_numinodes;

    res = back_end_replace(be, &k, &hdr, sizeof(hdr));
    if (res != 0)
        goto err1;

    return back_end_trans_commit(be);

err2:
    back_end_iter_free(iter);
err1:
    back_end_trans_abort(be);
    return res;
}

static void
foreach_alloc_cb(uint64_t sz, int dealloc, void *ctx)
{
    struct foreach_alloc_ctx *actx;

    if (dealloc)
        return;

    actx = (struct foreach_alloc_ctx *)ctx;

    actx->tot_sz += sz;

    fprintf(actx->f, "Allocation: %14" PRIu64 " bytes "
                     "(total %14" PRIu64 " bytes)\n",
            sz, actx->tot_sz);
}

static int
init_ver_3_to_4(struct back_end *be, size_t hdrlen, size_t jlen, int ro,
                int fmtconv)
{
    int res;
    size_t db_hdrlen;
    struct db_alloc_cb alloc_cb;
    struct db_key k;
    struct db_obj_header hdr;
    struct foreach_alloc_ctx actx;

    (void)jlen;
    (void)ro;
    (void)fmtconv;

    k.type = TYPE_HEADER;

    res = back_end_look_up(be, &k, NULL, &hdr, NULL, 0);
    if (res != 1)
        return (res == 0) ? -EILSEQ : res;

    res = back_end_ctl(be, BACK_END_DBM_OP_GET_HDR_LEN, &db_hdrlen);
    if (res != 0)
        return res;

    actx.f = stderr;
    actx.tot_sz = 0;

    alloc_cb.alloc_cb = &foreach_alloc_cb;
    alloc_cb.alloc_cb_ctx = &actx;

    res = back_end_ctl(be, BACK_END_DBM_OP_FOREACH_ALLOC, &alloc_cb);
    if ((res != 0) && (res != -ENOSPC))
        return res;

    hdr.usedbytes = hdrlen + db_hdrlen + actx.tot_sz;

    fprintf(stderr, "Total allocated space: %" PRIu64 " bytes\n",
            hdr.usedbytes);

    hdr.version = 4;

    return back_end_replace(be, &k, &hdr, sizeof(hdr));
}

static int
init_ver_4_to_5(struct back_end *be, size_t hdrlen, size_t jlen, int ro,
                int fmtconv)
{
    int res;
    struct db_key k;
    struct db_obj_header hdr;

    (void)hdrlen;
    (void)ro;
    (void)fmtconv;

    k.type = TYPE_HEADER;

    res = back_end_look_up(be, &k, NULL, &hdr, NULL, 0);
    if (res != 1)
        return (res == 0) ? -EILSEQ : res;

    hdr.usedbytes += jlen;

    fprintf(stderr,
            "Journal area size: %zu bytes\n"
            "Total allocated space: %" PRIu64 " bytes\n",
            jlen, hdr.usedbytes);

    hdr.version = 5;

    return back_end_replace(be, &k, &hdr, sizeof(hdr));
}

/*
 * Format v5 to v6 conversion:
 * For each TYPE_PAGE object in back end
 * - If I-node number is different from previous object
 *   1. Update st_blocks field in TYPE_STAT object with previous I-node number
 *      to equal current page count
 *   2. Reset current page count to 0
 * - Otherwise, increment current page count
 */
static int
init_ver_5_to_6(struct back_end *be, size_t hdrlen, size_t jlen, int ro,
                int fmtconv)
{
    fuse_ino_t ino;
    int res;
    struct back_end_iter *iter;
    struct db_key k;
    struct db_obj_header hdr;
    struct db_obj_stat s;

    (void)hdrlen;
    (void)jlen;
    (void)ro;
    (void)fmtconv;

    res = back_end_trans_new(be);
    if (res != 0)
        return res;

    for (k.ino = 0;; k.ino = ino + 1) {
        blkcnt_t n;
        int end = 0;

        res = back_end_iter_new(&iter, be);
        if (res != 0)
            goto err1;

        k.type = TYPE_PAGE;

        res = back_end_iter_search(iter, &k);
        if (res < 0)
            goto err2;

        res = back_end_iter_get(iter, &k, NULL, NULL);
        if (res != 0)
            goto err2;

        if (k.type != TYPE_PAGE) {
            back_end_iter_free(iter);
            break;
        }
        ino = k.ino;

        for (n = 1;; n++) {
            res = back_end_iter_next(iter);
            if (res != 0) {
                if (res != -ENOENT)
                    goto err2;
                end = 1;
                break;
            }

            res = back_end_iter_get(iter, &k, NULL, NULL);
            if (res != 0)
                goto err2;

            if (k.type != TYPE_PAGE) {
                end = 1;
                break;
            }
            if (k.ino != ino)
                break;
        }

        back_end_iter_free(iter);

        k.type = TYPE_STAT;
        k.ino = ino;

        res = back_end_look_up(be, &k, NULL, &s, NULL, 0);
        if (res != 1) {
            if (res == 0)
                res = -EIO;
            goto err1;
        }

        s.st_blocks = n * BLOCKS_PER_PG;

        fprintf(stderr, "Updating st_blocks for I-node %" PRIu64 " to %" PRIi64
                        "\n",
                k.ino, (int64_t)(s.st_blocks));

        res = back_end_replace(be, &k, &s, sizeof(s));
        if (res != 0)
            goto err1;

        if (end || (ino == ULONG_MAX))
            break;
    }

    k.type = TYPE_HEADER;

    res = back_end_look_up(be, &k, NULL, &hdr, NULL, 0);
    if (res != 1) {
        if (res == 0)
            res = -EIO;
        goto err1;
    }

    hdr.version = 6;

    res = back_end_replace(be, &k, &hdr, sizeof(hdr));
    if (res != 0)
        goto err1;

    return back_end_trans_commit(be);

err2:
    back_end_iter_free(iter);
err1:
    back_end_trans_abort(be);
    return res;
}

int
compat_init(struct back_end *be, uint64_t user_ver, uint64_t fs_ver,
            size_t hdrlen, size_t jlen, int ro, int fmtconv)
{
    int ret;
    size_t i;

    static const struct ent {
        uint64_t        user_ver;
        uint64_t        fs_ver;
        check_init_fn_t *check_init;
        init_fn_t       *init;
    } conv_fns[] = {
        {2, 3, &check_init_ro_or_fmtconv, &init_ver_2_to_3},
        {3, 4, &check_init_ro_or_fmtconv, &init_ver_3_to_4},
        {4, 5, &check_init_default,       &init_ver_4_to_5},
        {5, 6, &check_init_ro_or_fmtconv, &init_ver_5_to_6}
    };

    if (user_ver != fs_ver) {
        for (i = 0; i < ARRAY_SIZE(conv_fns); i++) {
            const struct ent *conv = &conv_fns[i];

            if ((conv->user_ver != user_ver) || (conv->fs_ver != fs_ver))
                continue;

            ret = (*(conv->check_init))(be, ro, fmtconv);
            if (ret != 1)
                return ret;

            syslog(LOG_NOTICE,
                   "Notice: updating format from version %" PRIu64 " to %"
                   PRIu64 "\n",
                   conv->user_ver, conv->fs_ver);

            return (*(conv->init))(be, hdrlen, jlen, ro, fmtconv);
        }

        return -EPROTONOSUPPORT;
    }

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
