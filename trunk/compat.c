/*
 * compat.c
 */

#include "back_end.h"
#include "compat.h"
#include "obj.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <fuse_lowlevel.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

typedef int check_init_fn_t(struct back_end *, int, int);
typedef int init_fn_t(struct back_end *, int, int);

int used_ino_set(uint64_t *, fuse_ino_t, fuse_ino_t, int);

static check_init_fn_t check_init_ro_or_fmtconv;

static init_fn_t init_ver_2_to_3;

static int
check_init_ro_or_fmtconv(struct back_end *be, int ro, int fmtconv)
{
    (void)be;

    if (ro)
        return 0;

    return fmtconv ? 1 : -EPROTONOSUPPORT;
}

/*
 * Format v2 to v3 conversion:
 * 1. Add used I-node number entry for each object of TYPE_STAT in back end
 * 2. Set FREE_INO_LAST_USED flag for last free I-node number object
 * 3. Set numinodes field in header object
 */
static int
init_ver_2_to_3(struct back_end *be, int ro, int fmtconv)
{
    int end;
    int res;
    struct back_end_iter *iter;
    struct db_key k, sk;
    struct db_obj_free_ino freeino;
    struct db_obj_header hdr;
    uint64_t numinodes, tot_numinodes;

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

int
compat_init(struct back_end *be, uint64_t user_ver, uint64_t fs_ver, int ro,
            int fmtconv)
{
    int ret;
    size_t i;

    static const struct {
        uint64_t        user_ver;
        uint64_t        fs_ver;
        check_init_fn_t *check_init;
        init_fn_t       *init;
    } conv_fns[] = {
        {2, 3, &check_init_ro_or_fmtconv, &init_ver_2_to_3}
    }, *conv;

    if (user_ver != fs_ver) {
        for (i = 0; i < ARRAY_SIZE(conv_fns); i++) {
            conv = &conv_fns[i];

            if ((conv->user_ver != user_ver) || (conv->fs_ver != fs_ver))
                continue;

            ret = (*(conv->check_init))(be, ro, fmtconv);
            if (ret != 1)
                return ret;

            syslog(LOG_NOTICE,
                   "Notice: updating format from version %" PRIu64 " to %"
                   PRIu64 "\n",
                   conv->user_ver, conv->fs_ver);

            return (*(conv->init))(be, ro, fmtconv);
        }

        return -EPROTONOSUPPORT;
    }

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
