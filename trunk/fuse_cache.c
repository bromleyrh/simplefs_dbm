/*
 * fuse_cache.c
 */

#include "back_end.h"
#include "fuse_cache.h"
#include "util.h"

#include <avl_tree.h>
#include <dbm_high_level.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/queue.h>

#define TRANS DB_HL_TRANS_GROUP
#define USER_TRANS DB_HL_TRANS_USER

struct data_ref {
    const void  *p;
    int         refcnt;
};

#define CACHE_OBJ_MAGIC 0x4a424f43

struct cache_obj {
    unsigned                magic;
    uint64_t                id; /* used for debugging */
    struct data_ref         *key;
    struct data_ref         *data;
    size_t                  datasize;
    int                     replace;
    int                     deleted;
    int                     destroyed;
    int                     in_cache;
    int                     lists;
    int                     refcnt;
    int                     chk_in_cache; /* used for consistency checking */
    int                     chk_lists;
    int                     chk_refcnt;
    LIST_ENTRY(cache_obj)   e;
};

enum op_type {
    INSERT = 1,
    DELETE
};

struct op {
    enum op_type        op;
    struct cache_obj    *obj;
};

struct key_ctx {
    struct cache_obj    *last_key;
    int                 last_key_valid;
};

LIST_HEAD(obj_list, cache_obj);

struct op_list {
    struct op   *ops;
    int         len;
    int         size;
    const char  *name;
};

struct fuse_cache {
    struct avl_tree             *cache;
    void                        *ctx;
    const struct back_end_ops   *ops;
    size_t                      key_size;
    struct key_ctx              key_ctx;
    back_end_key_cmp_t          key_cmp;
    struct obj_list             objs;
    struct op_list              ops_group;
    struct op_list              ops_user;
    void                        (*dump_cb)(FILE *, const void *, const void *,
                                           size_t, const char *, void *);
    void                        *dump_ctx;
    uint64_t                    cur_id;
    int                         trans_state;
    int                         replay;
};

struct fuse_cache_iter {
    void                *iter;
    avl_tree_iter_t     citer;
    void                *biter;
    struct cache_obj    *o;
    void                *key;
    void                *minkey;
    struct fuse_cache   *cache;
};

#define OP_LIST_INIT_SIZE 128

#define MAX_CLEAN_ENTRIES 512

#define CACHE_OBJ_VALID(obj) ((obj)->magic == CACHE_OBJ_MAGIC)

int back_end_dbm_get_trans_state(void *);

static void trans_cb(int, int, int, void *);

static int cache_obj_cmp(const void *, const void *, void *);
static int cache_obj_cmp_chk(const void *, const void *, void *);

static int obj_free_cb(const void *, void *);
static int obj_verify_refcnt_cb(const void *, void *);

static int chk_process_cache_refs(struct avl_tree *, struct avl_tree *);
static int chk_process_list_refs(struct avl_tree *, int, struct op_list *);

static int verify_refcnts(struct avl_tree *);
static int verify_list(struct obj_list *, struct fuse_cache *);

static void check_consistency(struct fuse_cache *);

static int op_list_init(struct op_list *, const char *);
static void op_list_destroy(struct op_list *);
static int op_list_reserve(struct op_list *, int);
static void op_list_add(struct op_list *, int, enum op_type,
                        struct cache_obj *);
static void op_list_roll_back(struct op_list *, int, struct op_list *, int,
                              struct fuse_cache *);
static int op_list_replay(struct op_list *, struct fuse_cache *);
static void op_list_clear(struct op_list *, int, int, struct fuse_cache *);
static void op_list_dump(FILE *, struct op_list *, struct fuse_cache *);

static int check_replay(struct fuse_cache *);

static int get_next_elem(void *, void *, size_t *, const void *,
                         struct fuse_cache *);

static int get_next_iter_elem(struct cache_obj *, void *, void **, size_t *,
                              size_t *, avl_tree_iter_t, void **, void **,
                              void **, struct fuse_cache *);
static int do_iter_get(void *, void *, void **, size_t *, size_t *,
                       struct fuse_cache *);
static int do_iter_search_cache(avl_tree_iter_t, const void *,
                                struct fuse_cache *);
static int do_iter_search_be(void *, const void *, struct fuse_cache *);

static int init_cache_obj(struct cache_obj *, const void *, const void *,
                          size_t, struct fuse_cache *);
static int destroy_cache_obj(struct cache_obj *, int);
static int return_cache_obj(const struct cache_obj *, void *, void *, size_t *,
                            struct fuse_cache *);

static int fuse_cache_create(void **, size_t, back_end_key_cmp_t, void *);
static int fuse_cache_open(void **, size_t, back_end_key_cmp_t, void *);
static int fuse_cache_close(void *);
static int fuse_cache_insert(void *, const void *, const void *, size_t);
static int fuse_cache_replace(void *, const void *, const void *, size_t);
static int fuse_cache_look_up(void *, const void *, void *, void *, size_t *,
                              int);
static int fuse_cache_delete(void *, const void *);
static int fuse_cache_walk(void *, back_end_walk_cb_t, void *);
static int fuse_cache_iter_new(void **, void *);
static int fuse_cache_iter_free(void *);
static int fuse_cache_iter_get(void *, void *, void *, size_t *);
static int fuse_cache_iter_next(void *);
static int fuse_cache_iter_search(void *, const void *);
static int fuse_cache_trans_new(void *);
static int fuse_cache_trans_abort(void *);
static int fuse_cache_trans_commit(void *);
static int fuse_cache_sync(void *);

const struct back_end_ops back_end_fuse_cache_ops = {
    .create         = &fuse_cache_create,
    .open           = &fuse_cache_open,
    .close          = &fuse_cache_close,
    .insert         = &fuse_cache_insert,
    .replace        = &fuse_cache_replace,
    .look_up        = &fuse_cache_look_up,
    .delete         = &fuse_cache_delete,
    .walk           = &fuse_cache_walk,
    .iter_new       = &fuse_cache_iter_new,
    .iter_free      = &fuse_cache_iter_free,
    .iter_get       = &fuse_cache_iter_get,
    .iter_next      = &fuse_cache_iter_next,
    .iter_search    = &fuse_cache_iter_search,
    .trans_new      = &fuse_cache_trans_new,
    .trans_abort    = &fuse_cache_trans_abort,
    .trans_commit   = &fuse_cache_trans_commit,
    .sync           = &fuse_cache_sync
};

/*
 * trans_cb():
 * This function must handle commit and abort events from the back end for both
 * group and user transactions. Handling successful commit events (where status
 * == 0) involves clearing the corresponding operation list(s) and optionally
 * removing from the cache each cache object deleted from a list. Unsuccessful
 * commit events can be ignored, as the back end guarantees a transaction commit
 * is retried until it succeeds.
 *
 * In most cases, transaction abort handling is more complex and requires the
 * use of one or both operation lists. Note that all abort events have a nonzero
 * status. When a group+user transaction is aborted, both a rollback operation
 * affecting the cache and a replay operation affecting the back end must be
 * carried out. The rollback operation involves traversing the user operation
 * list in reverse and applying the inverse of each operation to the cache while
 * removing it from both the user and group operation lists. The replay
 * operation is performed second and applies each remaining operation in the
 * group operation list to the back end in order. This replay operation must be
 * retried until successful. The cache must continue to allow lookups and
 * traversals but return an error for modifying operations until the replay
 * operation succeeds.
 *
 * When a group transaction is aborted, a replay operation affecting the back
 * end is performed, as described above. Also as mentioned above, the cache
 * must continue to permit lookup operations and return errors for other
 * operations until this replay succeeds.
 *
 * A user transaction abort requires a rollback operation affecting the cache,
 * as performed in the handling of a group+user transaction abort.
 */
static void
trans_cb(int trans_type, int act, int status, void *ctx)
{
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    static const char *const type2str[] = {
        [DB_HL_TRANS_GROUP]                     = "group",
        [DB_HL_TRANS_USER]                      = "user",
        [DB_HL_TRANS_GROUP | DB_HL_TRANS_USER]  = "group+user"
    };

    static const char *const act2str[] = {
        [DB_HL_ACT_NEW]     = "new",
        [DB_HL_ACT_ABORT]   = "abort",
        [DB_HL_ACT_COMMIT]  = "commit"
    };

    fprintf(stderr,
            "Transaction data:\n"
            "\tType: %s transaction\n"
            "\tAction: %s\n"
            "\tStatus: %d\n",
            type2str[trans_type], act2str[act], status);

    if ((status != 0) && (act != DB_HL_ACT_ABORT))
        return;

    switch (act) {
    case DB_HL_ACT_NEW:
        cache->trans_state |= trans_type;
        break;
    case DB_HL_ACT_ABORT:
        cache->trans_state &= ~trans_type;
        if (cache->replay != 2) {
            if (trans_type & DB_HL_TRANS_USER) {
                op_list_roll_back(&cache->ops_user, USER_TRANS,
                                  &cache->ops_group, TRANS, cache);
            }
            if ((trans_type & DB_HL_TRANS_GROUP)
                && (op_list_replay(&cache->ops_group, cache) != 0))
                cache->replay = 1;
        }
        break;
    case DB_HL_ACT_COMMIT:
        cache->trans_state &= ~trans_type;
        /* clear appropriate operation lists */
        if (cache->replay == 2)
            abort();
        if (trans_type & DB_HL_TRANS_USER)
            op_list_clear(&cache->ops_user, USER_TRANS, 1, cache);
        if (trans_type & DB_HL_TRANS_GROUP)
            op_list_clear(&cache->ops_group, TRANS, 1, cache);
        break;
    default:
        abort();
    }

    check_consistency(cache);
}

static int
cache_obj_cmp(const void *k1, const void *k2, void *ctx)
{
    struct cache_obj *o1 = *(struct cache_obj **)k1;
    struct cache_obj *o2 = *(struct cache_obj **)k2;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    if (cache->key_ctx.last_key_valid != -1) {
        cache->key_ctx.last_key = o2;
        cache->key_ctx.last_key_valid = 1;
    }

    return (*(cache->key_cmp))(o1->key->p, o2->key->p, NULL);
}

static int
cache_obj_cmp_chk(const void *k1, const void *k2, void *ctx)
{
    struct cache_obj *o1 = *(struct cache_obj **)k1;
    struct cache_obj *o2 = *(struct cache_obj **)k2;

    (void)ctx;

    return (o1 > o2) - (o1 < o2);
}

static int
obj_free_cb(const void *k, void *ctx)
{
    struct cache_obj *o = *(struct cache_obj **)k;

    (void)ctx;

    o->in_cache = 0;

    destroy_cache_obj(o, 1);
    free(o);

    return 0;
}

static int
obj_verify_refcnt_cb(const void *k, void *ctx)
{
    struct cache_obj *o = *(struct cache_obj **)k;

    (void)ctx;

    if (o->in_cache != o->chk_in_cache) {
        fputs("Object has incorrect in_cache status\n", stderr);
        return -EIO;
    }
    if (o->lists != o->chk_lists) {
        fputs("Object has incorrect list membership flags\n", stderr);
        return -EIO;
    }
    if (o->refcnt != o->chk_refcnt) {
        fputs("Object has incorrect refcnt\n", stderr);
        return -EIO;
    }

    return 0;
}

/*
 * Note: This function assumes the object set referenced by objs is empty
 */
static int
chk_process_cache_refs(struct avl_tree *objs, struct avl_tree *cache)
{
    avl_tree_iter_t iter;
    int res;

    res = avl_tree_iter_new(&iter, cache);
    if (res != 0)
        return (res == -ENOENT) ? 0 : res;

    for (;;) {
        struct cache_obj *o;

        res = avl_tree_iter_get(iter, &o);
        if (res != 0)
            goto err;
        assert(CACHE_OBJ_VALID(o));

        if (!(o->in_cache)) {
            fputs("Object in cache has in_cache status 0\n", stderr);
            goto chk_err;
        }
        if (o->refcnt < 1) {
            fprintf(stderr, "Object in cache has invalid refcnt %d\n",
                    o->refcnt);
            goto chk_err;
        }

        o->chk_in_cache = 1;
        o->chk_lists = 0;
        o->chk_refcnt = 1;

        res = avl_tree_insert(objs, &o);
        if (res != 0)
            goto err;

        res = avl_tree_iter_next(iter);
        if (res != 0) {
            if (res != -EADDRNOTAVAIL)
                goto err;
            break;
        }
    }

    avl_tree_iter_free(iter);

    return 0;

chk_err:
    res = -EIO;
err:
    avl_tree_iter_free(iter);
    return res;
}

static int
chk_process_list_refs(struct avl_tree *objs, int which, struct op_list *list)
{
    int i;
    int res;

    for (i = 0; i < list->len; i++) {
        struct cache_obj *o = list->ops[i].obj;

        assert(CACHE_OBJ_VALID(o));

        if (!(o->lists & which)) {
            fprintf(stderr, "Object in list %s does not have list flag set\n",
                    list->name);
            return -EIO;
        }
        if (o->refcnt < 1) {
            fprintf(stderr, "Object in list %s has invalid refcnt %d\n",
                    list->name, o->refcnt);
            return -EIO;
        }

        res = avl_tree_search(objs, &o, &o);
        if (res != 0) {
            if (res != 1)
                return res;
            o->chk_lists |= which;
            ++(o->chk_refcnt);
            continue;
        }

        o->chk_in_cache = 0;
        o->chk_lists = which;
        o->chk_refcnt = 1;

        res = avl_tree_insert(objs, &o);
        if (res != 0)
            return res;
    }

    return 0;
}

static int
verify_refcnts(struct avl_tree *objs)
{
    avl_tree_walk_ctx_t wctx = NULL;

    return avl_tree_walk(objs, NULL, &obj_verify_refcnt_cb, NULL, &wctx);
}

static int
verify_list(struct obj_list *list, struct fuse_cache *cache)
{
    const char *errmsg;
    int i;
    int res;
    struct cache_obj *o;

    LIST_FOREACH(o, list, e) {
        int in_cache, in_list;
        struct cache_obj *o_tmp;

        if (o->destroyed) /* object may be inconsistent: skip */
            continue;

        if (o->refcnt == 0) {
            errmsg = "Object in global list has refcnt 0";
            goto err;
        }
        if (!(o->in_cache) && (o->lists == 0)) {
            errmsg = "Object in global list has in_cache status 0 and list "
                     "flags 0";
            goto err;
        }

        res = avl_tree_search(cache->cache, &o, &o_tmp);
        if (res == 1)
            in_cache = 1;
        else if (res == 0) {
            if (o->in_cache) {
                errmsg = "Object not in cache has in_cache status 1";
                goto err;
            }
            in_cache = 0;
        } else
            return res;

        in_list = 0;
        for (i = 0; i < cache->ops_group.len; i++) {
            if (o == cache->ops_group.ops[i].obj) {
                in_list = 1;
                break;
            }
        }
        if (!in_list && (o->lists & TRANS)) {
            errmsg = "Object not in group operation list has group operation "
                     "flag set";
            goto err;
        }

        for (i = 0; i < cache->ops_user.len; i++) {
            if (o == cache->ops_user.ops[i].obj) {
                in_list |= 2;
                break;
            }
        }
        if (!(in_list & 2) && (o->lists & USER_TRANS)) {
            errmsg = "Object not in user operation list has user operation "
                     "flag set";
            goto err;
        }
        if (!in_cache && !in_list) {
            errmsg = "Object in global list not referenced";
            goto err;
        }
    }

    return 0;

err:
    fprintf(stderr, "%s\n", errmsg);
    abort();
    return -EIO;
}

static void
check_consistency(struct fuse_cache *cache)
{
    int err;
    struct avl_tree *objs;

    /* check transaction state */
    if (cache->trans_state != back_end_dbm_get_trans_state(cache->ctx)) {
        fputs("Cache transaction state and back end transaction state differ\n",
              stderr);
        err = -EIO;
        goto err;
    }

    /* check reference counts */

    err = avl_tree_new(&objs, sizeof(struct cache_obj *), &cache_obj_cmp_chk, 0,
                       NULL, cache, NULL);
    if (err)
        goto err;

    err = chk_process_cache_refs(objs, cache->cache);
    if (err)
        goto err;

    err = chk_process_list_refs(objs, TRANS, &cache->ops_group);
    if (err)
        goto err;
    err = chk_process_list_refs(objs, USER_TRANS, &cache->ops_user);
    if (err)
        goto err;

    err = verify_refcnts(objs);
    if (err)
        goto err;

    avl_tree_free(objs);

    /* check cache objects */
    err = verify_list(&cache->objs, cache);
    if (err)
        goto err;

    fputs("Consistency check passed\n", stderr);

    return;

err:
    fprintf(stderr, "Consistency check encountered error %d\n", err);
    abort();
}

static int
op_list_init(struct op_list *list, const char *name)
{
    struct op *ops;

    ops = do_malloc(OP_LIST_INIT_SIZE * sizeof(*ops));
    if (ops == NULL)
        return -errno;

    list->ops = ops;
    list->len = 0;
    list->size = OP_LIST_INIT_SIZE;
    list->name = name;

    return 0;
}

static void
op_list_destroy(struct op_list *list)
{
    free(list->ops);
}

static int
op_list_reserve(struct op_list *list, int num)
{
    int newlen = list->len + num;

    if (newlen > list->size) {
        int newsz = newlen * 2;
        struct op *tmp;

        tmp = do_realloc(list->ops, newsz * sizeof(*tmp));
        if (tmp == NULL)
            return -errno;

        list->ops = tmp;
        list->size = newsz;
    }

    return 0;
}

static void
op_list_add(struct op_list *list, int which, enum op_type type,
            struct cache_obj *obj)
{
    struct op *op;

    assert(list->len < list->size);

    op = &list->ops[list->len];
    op->op = type;
    op->obj = (struct cache_obj *)obj;

    ++(list->len);

    obj->lists |= which;
    ++(obj->refcnt);
}

static void
op_list_roll_back(struct op_list *list, int which, struct op_list *list_other,
                  int which_other, struct fuse_cache *cache)
{
    int err;
    int i, j;

    j = list_other->len;
    for (i = list->len - 1; i >= 0; i--) {
        struct cache_obj *obj;
        struct op *op = &list->ops[i];

        obj = op->obj;

        switch (op->op) {
        case INSERT:
            /* delete key from cache */
            err = avl_tree_delete(cache->cache, &obj);
            if (err)
                abort();
            obj->in_cache = 0;
            --(obj->refcnt);
            break;
        case DELETE:
            /* reinsert key into cache */
            err = avl_tree_insert(cache->cache, &obj);
            if (err) {
                if (err != -EADDRINUSE)
                    abort();
                obj->deleted = 0;
            } else {
                obj->in_cache = 1;
                ++(obj->refcnt);
            }
            break;
        default:
            abort();
        }

        if (j > 0) {
            struct cache_obj *obj_other = list_other->ops[j-1].obj;

            if (obj_other == obj) {
                obj_other->lists &= ~which_other;
                --(obj_other)->refcnt;
                --j;
            }
        }
    }

    op_list_clear(list, which, 0, cache);
    list_other->len = j;
}

static int
op_list_replay(struct op_list *list, struct fuse_cache *cache)
{
    int err = 0;
    int i;
    int prev_replay;

    prev_replay = cache->replay;
    cache->replay = 2;

    for (i = 0; i < list->len; i++) {
        struct cache_obj *obj;
        struct op *op = &list->ops[i];

        obj = op->obj;

        switch (op->op) {
        case INSERT:
            if (obj->replace == 1) { /* replace key in back end */
                err = (*(cache->ops->replace))(cache->ctx, obj->key->p,
                                               obj->data->p, obj->datasize);
            } else { /* insert key into back end */
                err = (*(cache->ops->insert))(cache->ctx, obj->key->p,
                                              obj->data->p, obj->datasize);
            }
            break;
        case DELETE:
            /* delete key from back end */
            err = (*(cache->ops->delete))(cache->ctx, obj->key->p);
            break;
        default:
            abort();
        }

        if (err)
            goto end;
    }

end:
    cache->replay = prev_replay;
    return err;
}

static void
op_list_clear(struct op_list *list, int which, int rem_from_cache,
              struct fuse_cache *cache)
{
    int i;

    for (i = 0; i < list->len; i++) {
        struct cache_obj *obj = list->ops[i].obj;

        obj->lists &= ~which;
        --(obj->refcnt);

        if (rem_from_cache && obj->in_cache) {
            if (avl_tree_delete(cache->cache, &obj) != 0)
                abort();
            obj->in_cache = 0;
            --(obj->refcnt);
        }

        if (destroy_cache_obj(obj, 0))
            free(obj);
    }

    list->len = 0;
}

static void
op_list_dump(FILE *f, struct op_list *list, struct fuse_cache *cache)
{
#ifdef DEBUG_DUMP
    int i;

    static const char *const op2str[] = {
        [INSERT] = "insert",
        [DELETE] = "delete"
    };

    if (cache->dump_cb == NULL)
        return;

    fprintf(f, "Operation list \"%s\"\n", list->name);

    for (i = 0; i < list->len; i++) {
        struct cache_obj *obj;
        struct op *op = &list->ops[i];

        obj = op->obj;

        fprintf(f, "\t%s%s:\n", op2str[op->op],
                obj->replace ? " (replace)" : "");

        (*(cache->dump_cb))(f, obj->key->p, obj->data->p, obj->datasize, "\t\t",
                            cache->dump_ctx);
    }
#else
    (void)f;
    (void)list;
    (void)cache;

    return;
#endif
}

static int
check_replay(struct fuse_cache *cache)
{
    int err;

    if (cache->replay) {
        err = op_list_replay(&cache->ops_group, cache);
        if (err)
            return err;
        cache->replay = 0;
    }

    return 0;
}

static int
get_next_elem(void *retkey, void *retdata, size_t *retdatasize, const void *key,
              struct fuse_cache *cache)
{
    avl_tree_iter_t iter;
    int res;
    size_t datalen;
    struct cache_obj *o;
    struct cache_obj obj;
    struct data_ref keyref;

    if (retdatasize == NULL)
        retdatasize = &datalen;

    res = avl_tree_iter_new(&iter, cache->cache);
    if (res != 0)
        return res;

    keyref.p = key;
    obj.key = &keyref;
    o = &obj;
    res = avl_tree_iter_search(iter, &o);
    if (res != 1) {
        if (res == 0)
            res = -ENOENT;
        goto end;
    }

    for (;;) {
        res = avl_tree_iter_next(iter);
        if (res != 0)
            goto end;

        res = avl_tree_iter_get(iter, &o);
        if (res != 0)
            goto end;

        if (!(o->deleted)) {
            res = return_cache_obj(o, retkey, retdata, retdatasize, cache);
            break;
        }
    }

end:
    avl_tree_iter_free(iter);
    return res;
}

static int
get_next_iter_elem(struct cache_obj *o, void *key, void **data, size_t *datalen,
                   size_t *datasize, avl_tree_iter_t citer, void **biter,
                   void **iter, void **minkey, struct fuse_cache *cache)
{
    int res;

    res = (*(cache->key_cmp))(o->key, key, NULL);
    if (res > 0) {
        *iter = *biter;
        *minkey = key;
        return 0;
    }

    if (res == 0) { /* skip duplicate element */
        res = (*(cache->ops->iter_next))(*biter);
        if (res != 0) {
            if (res != -EADDRNOTAVAIL)
                return res;
            (*(cache->ops->iter_free))(*biter);
            *biter = NULL;
        } else {
            res = do_iter_get(*biter, key, data, datalen, datasize, cache);
            if (res != 0)
                return res;
        }
    }

    *iter = citer;
    *minkey = (void *)(o->key->p);
    return 0;
}

static int
do_iter_get(void *iter, void *key, void **data, size_t *datalen,
            size_t *datasize, struct fuse_cache *cache)
{
    int res;
    size_t len;

    if (data == NULL)
        return (*(cache->ops->iter_get))(iter, key, NULL, NULL);

    res = (*(cache->ops->iter_get))(iter, NULL, NULL, &len);
    if (res != 0)
        return res;

    if (len > *datalen) {
        void *tmp;

        tmp = do_realloc(*data, len);
        if (tmp == NULL)
            return -errno;
        *data = tmp;
        *datasize = len;
    }

    res = (*(cache->ops->iter_get))(iter, key, *data, &len);
    if (res == 0) {
        assert(len <= *datasize);
        *datalen = len;
    }

    return 0;
}

static int
do_iter_search_cache(avl_tree_iter_t iter, const void *key,
                     struct fuse_cache *cache)
{
    int res;
    struct cache_obj *o;
    struct cache_obj obj;
    struct data_ref keyref;

    keyref.p = key;
    obj.key = &keyref;
    o = &obj;

    res = avl_tree_iter_search(iter, &o);
    if (res != 0)
        return (res == 1) ? 0 : res;

    o = cache->key_ctx.last_key;

    res = avl_tree_iter_search(iter, &o);
    assert(res != 0);
    if (res < 0)
        return res;

    if ((*(cache->key_cmp))(cache->key_ctx.last_key->key, key, NULL) < 0) {
        res = avl_tree_iter_next(iter);
        if (res != 0)
            return res;
    }

    for (;;) {
        res = avl_tree_iter_get(iter, &o);
        if (res != 0)
            return res;

        if (!(o->deleted))
            break;

        res = avl_tree_iter_next(iter);
        if (res != 0)
            return res;
    }

    return 0;
}

static int
do_iter_search_be(void *iter, const void *key, struct fuse_cache *cache)
{
    int res;

    res = (*(cache->ops->iter_search))(iter, key);
    return (res == 1) ? 0 : res;
}

static int
init_cache_obj(struct cache_obj *o, const void *key, const void *data,
               size_t datasize, struct fuse_cache *cache)
{
    int err;
    struct data_ref *keyref, *dataref;
    void *k, *d;

    keyref = do_malloc(sizeof(*keyref));
    if (keyref == NULL)
        return -errno;
    dataref = do_malloc(sizeof(*dataref));
    if (dataref == NULL) {
        err = -errno;
        goto err1;
    }

    k = do_malloc(cache->key_size);
    if (k == NULL) {
        err = -errno;
        goto err2;
    }
    d = do_malloc(datasize);
    if (d == NULL) {
        err = -errno;
        goto err3;
    }

    o->id = (cache->cur_id)++;

    memcpy(k, key, cache->key_size);
    memcpy(d, data, datasize);

    keyref->p = k;
    keyref->refcnt = 1;
    dataref->p = d;
    dataref->refcnt = 1;

    o->key = keyref;
    o->data = dataref;
    o->datasize = datasize;
    o->replace = 0;
    o->deleted = 0;

    o->destroyed = 0;

    o->in_cache = o->lists = 0;
    o->refcnt = o->chk_refcnt = 0;

    LIST_INSERT_HEAD(&cache->objs, o, e);

    o->magic = CACHE_OBJ_MAGIC;

    return 0;

err3:
    free(k);
err2:
    free(dataref);
err1:
    free(keyref);
    return err;
}

static int
update_cache_obj(struct cache_obj *o, const void *key, const void *data,
                 size_t datasize, struct fuse_cache *cache)
{
    void *d;

    d = do_malloc(datasize);
    if (d == NULL)
        return -errno;

    memcpy((void *)(o->key->p), key, cache->key_size);

    memcpy(d, data, datasize);
    free((void *)(o->data->p));
    o->data->p = d;
    o->datasize = datasize;

    return 0;
}

static int
destroy_cache_obj(struct cache_obj *o, int force)
{
    if (force || (o->refcnt == 0)) {
        assert(!(o->in_cache));
        assert(o->lists == 0);
        LIST_REMOVE(o, e);
        if (--(o->key->refcnt) == 0) {
            free((void *)(o->key->p));
            free(o->key);
        }
        if (--(o->data->refcnt) == 0) {
            free((void *)(o->data->p));
            free(o->data);
        }
        o->magic = 0;
        return 1;
    }

    return 0;
}

static int
return_cache_obj(const struct cache_obj *o, void *retkey, void *retdata,
                 size_t *retdatasize, struct fuse_cache *cache)
{
    if (retkey != NULL)
        memcpy(retkey, o->key->p, cache->key_size);
    if (retdata != NULL)
        memcpy(retdata, o->data->p, o->datasize);
    if (retdatasize != NULL)
        *retdatasize = o->datasize;

    return 1;
}

static int
fuse_cache_create(void **ctx, size_t key_size, back_end_key_cmp_t key_cmp,
                  void *args)
{
    int err;
    struct fuse_cache *ret;
    struct fuse_cache_args *cache_args = (struct fuse_cache_args *)args;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    ret->key_ctx.last_key = NULL;
    ret->key_ctx.last_key_valid = 0;

    err = avl_tree_new(&ret->cache, sizeof(struct cache_obj *), &cache_obj_cmp,
                       0, NULL, ret, NULL);
    if (err)
        goto err1;

    LIST_INIT(&ret->objs);

    err = op_list_init(&ret->ops_group, "group");
    if (err)
        goto err2;
    err = op_list_init(&ret->ops_user, "user");
    if (err)
        goto err3;

    (*(cache_args->set_trans_cb))(cache_args->args, &trans_cb, ret);

    err = (*(cache_args->ops->create))(&ret->ctx, key_size, key_cmp,
                                       cache_args->args);
    if (err)
        goto err4;

    ret->ops = cache_args->ops;

    ret->dump_cb = NULL;
    ret->dump_ctx = NULL;

    ret->cur_id = 0;

    ret->trans_state = 0;
    ret->replay = 0;

    *ctx = ret;
    return 0;

err4:
    op_list_destroy(&ret->ops_user);
err3:
    op_list_destroy(&ret->ops_group);
err2:
    avl_tree_free(ret->cache);
err1:
    free(ret);
    return err;
}

static int
fuse_cache_open(void **ctx, size_t key_size, back_end_key_cmp_t key_cmp,
                void *args)
{
    int err;
    struct fuse_cache *ret;
    struct fuse_cache_args *cache_args = (struct fuse_cache_args *)args;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    ret->key_ctx.last_key = NULL;
    ret->key_ctx.last_key_valid = 0;

    err = avl_tree_new(&ret->cache, sizeof(struct cache_obj *), &cache_obj_cmp,
                       0, NULL, ret, NULL);
    if (err)
        goto err1;

    LIST_INIT(&ret->objs);

    err = op_list_init(&ret->ops_group, "group");
    if (err)
        goto err2;
    err = op_list_init(&ret->ops_user, "user");
    if (err)
        goto err3;

    (*(cache_args->set_trans_cb))(cache_args->args, &trans_cb, ret);

    err = (*(cache_args->ops->open))(&ret->ctx, key_size, key_cmp,
                                     cache_args->args);
    if (err)
        goto err4;

    ret->ops = cache_args->ops;

    ret->dump_cb = NULL;
    ret->dump_ctx = NULL;

    ret->cur_id = 0;

    ret->trans_state = 0;
    ret->replay = 0;

    *ctx = ret;
    return 0;

err4:
    op_list_destroy(&ret->ops_user);
err3:
    op_list_destroy(&ret->ops_group);
err2:
    avl_tree_free(ret->cache);
err1:
    free(ret);
    return err;
}

static int
fuse_cache_close(void *ctx)
{
    avl_tree_walk_ctx_t wctx = NULL;
    int err, tmp;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    err = (*(cache->ops->close))(cache->ctx);

    op_list_clear(&cache->ops_group, TRANS, 1, cache);
    op_list_clear(&cache->ops_user, USER_TRANS, 1, cache);

    avl_tree_walk(cache->cache, NULL, &obj_free_cb, NULL, &wctx);

    tmp = avl_tree_free(cache->cache);
    if (tmp != 0)
        err = tmp;

    op_list_destroy(&cache->ops_group);
    op_list_destroy(&cache->ops_user);

    free(cache);

    return err;
}

static int
fuse_cache_insert(void *ctx, const void *key, const void *data, size_t datasize)
{
    int res;
    int trans_state;
    struct cache_obj *o, *o_old;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    op_list_dump(stderr, &cache->ops_group, cache);
    op_list_dump(stderr, &cache->ops_user, cache);

    res = check_replay(cache);
    if (res != 0)
        return res;

    res = op_list_reserve(&cache->ops_group, 1);
    if (res != 0)
        return res;
    res = op_list_reserve(&cache->ops_user, 1);
    if (res != 0)
        return res;

    /* insert into cache */

    o = do_malloc(sizeof(*o));
    if (o == NULL)
        return -errno;

    res = init_cache_obj(o, key, data, datasize, cache);
    if (res != 0)
        goto err1;

    res = avl_tree_insert(cache->cache, &o);
    if (res != 0) {
        if (res != -EADDRINUSE)
            goto err2;

        res = avl_tree_search(cache->cache, &o, &o_old);
        if (res != 1) {
            if (res == 0)
                res = -EIO;
            goto err2;
        }
        assert(CACHE_OBJ_VALID(o_old));

        if (!(o_old->deleted)) {
            res = -EADDRINUSE;
            goto err2;
        }

        destroy_cache_obj(o, 1);
        free(o);

        res = update_cache_obj(o_old, key, data, datasize, cache);
        if (res != 0)
            return res;

        o_old->deleted = 0;

        goto end;
    }
    o->in_cache = 1;
    ++(o->refcnt);

    /* insert into back end */
    res = (*(cache->ops->insert))(cache->ctx, key, data, datasize);
    if (res != 0)
        goto err3;

    trans_state = cache->trans_state;

    /* add insert operation to appropriate operation lists */
    if (trans_state & TRANS)
        op_list_add(&cache->ops_group, TRANS, INSERT, o);
    if (trans_state & USER_TRANS)
        op_list_add(&cache->ops_user, USER_TRANS, INSERT, o);

end:
    check_consistency(cache);
    return 0;

err3:
    avl_tree_delete(cache->cache, &o);
err2:
    destroy_cache_obj(o, 1);
err1:
    free(o);
    return res;
}

static int
fuse_cache_replace(void *ctx, const void *key, const void *data,
                   size_t datasize)
{
    int in_cache = 0;
    int o_old_destroyed = 0;
    int res;
    int trans_state;
    struct cache_obj *o, *o_old;
    struct data_ref keyref;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    op_list_dump(stderr, &cache->ops_group, cache);
    op_list_dump(stderr, &cache->ops_user, cache);

    res = check_replay(cache);
    if (res != 0)
        return res;

    res = op_list_reserve(&cache->ops_group, 2);
    if (res != 0)
        return res;
    res = op_list_reserve(&cache->ops_user, 2);
    if (res != 0)
        return res;

    o = do_malloc(sizeof(*o));
    if (o == NULL)
        return -errno;

    /* replace in cache */
    keyref.p = key;
    o->key = &keyref;
    res = avl_tree_search(cache->cache, &o, &o_old);
    if (res == 1) { /* key in cache */
        assert(CACHE_OBJ_VALID(o_old));
        if (o_old->deleted) {
            res = -EADDRNOTAVAIL;
            goto err1;
        }
        res = avl_tree_delete(cache->cache, &o_old);
        if (res != 0)
            goto err1;
        o_old->in_cache = 0;
        if (--(o_old->refcnt) == 0)
            o_old->destroyed = o_old_destroyed = 1;
        res = init_cache_obj(o, key, data, datasize, cache);
        if (res != 0)
            goto err2;
        if (avl_tree_insert(cache->cache, &o) != 0)
            abort();
        in_cache = 1;
    } else if (res == 0) {
        /* key not in cache */
        res = init_cache_obj(o, key, data, datasize, cache);
        if (res != 0)
            goto err1;
        res = avl_tree_insert(cache->cache, &o);
        if (res != 0) {
            destroy_cache_obj(o, 1);
            goto err1;
        }
    } else
        goto err1;

    o->replace = 1;
    o->in_cache = 1;
    ++(o->refcnt);

    /* replace in back end */
    res = (*(cache->ops->replace))(cache->ctx, key, data, datasize);
    if (res != 0) {
        if (!in_cache) {
            avl_tree_delete(cache->cache, &o);
            destroy_cache_obj(o, 1);
            goto err1;
        }
        if (res != -EADDRNOTAVAIL) {
            destroy_cache_obj(o, 1);
            goto err3;
        }
        /* object in cache but not back end */
    }

    trans_state = cache->trans_state;

    /* add insert operation and possibly delete operation to appropriate
       lists */
    if (trans_state & TRANS) {
        if (in_cache) {
            op_list_add(&cache->ops_group, TRANS, DELETE, o_old);
            o_old->destroyed = o_old_destroyed = 0;
            o->replace = 2;
        }
        op_list_add(&cache->ops_group, TRANS, INSERT, o);
    }
    if (trans_state & USER_TRANS) {
        if (in_cache) {
            op_list_add(&cache->ops_user, USER_TRANS, DELETE, o_old);
            o_old->destroyed = o_old_destroyed = 0;
            o->replace = 2;
        }
        op_list_add(&cache->ops_user, USER_TRANS, INSERT, o);
    }

    if (in_cache && o_old_destroyed) {
        destroy_cache_obj(o_old, 1);
        free(o_old);
    }

    check_consistency(cache);
    return 0;

err3:
    avl_tree_delete(cache->cache, &o);
err2:
    if (avl_tree_insert(cache->cache, &o_old) != 0)
        abort();
    o_old->in_cache = 1;
    ++(o_old->refcnt);
err1:
    free(o);
    return res;
}

static int
fuse_cache_look_up(void *ctx, const void *key, void *retkey, void *retdata,
                   size_t *retdatasize, int look_up_nearest)
{
    int res;
    struct cache_obj *o;
    struct cache_obj obj;
    struct data_ref keyref;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    op_list_dump(stderr, &cache->ops_group, cache);
    op_list_dump(stderr, &cache->ops_user, cache);

    /* look up in cache */
    keyref.p = key;
    obj.key = &keyref;
    o = &obj;
    res = avl_tree_search(cache->cache, &o, &o);
    if (res != 0) {
        if (res == 1) {
            assert(CACHE_OBJ_VALID(o));
            if (o->deleted)
                res = 0;
        }
        goto out_cache;
    }

    /* look up in back end */
    res = (*(cache->ops->look_up))(cache->ctx, key, retkey, retdata,
                                   retdatasize, 0);
    if (!look_up_nearest || (res != 0))
        return res;

    /* look up nearest key in cache */

    cache->key_ctx.last_key_valid = 0;

    res = avl_tree_search(cache->cache, &o, &o);

    assert(res == 0);
    if (cache->key_ctx.last_key_valid) {
        int cmp;

        cmp = (*(cache->key_cmp))(cache->key_ctx.last_key->key, key, NULL);
        if (cmp > 0) {
            o = cache->key_ctx.last_key;
            res = avl_tree_search(cache->cache, &o, &o);
            if (res == 1)
                assert(CACHE_OBJ_VALID(o));
            else
                assert(res != 0);
            goto out_cache;
        }
        res = get_next_elem(retkey, retdata, retdatasize,
                            cache->key_ctx.last_key->key, cache);
        return (res == -EADDRNOTAVAIL) ? 0 : res;
    }

    /* look up nearest key in back end */
    return (*(cache->ops->look_up))(cache->ctx, key, retkey, retdata,
                                    retdatasize, 1);

out_cache:
    return (res == 1)
           ? return_cache_obj(o, retkey, retdata, retdatasize, cache) : res;
}

static int
fuse_cache_delete(void *ctx, const void *key)
{
    int in_cache = 0;
    int res;
    int trans_state;
    struct cache_obj *o;
    struct cache_obj obj;
    struct data_ref keyref;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    op_list_dump(stderr, &cache->ops_group, cache);
    op_list_dump(stderr, &cache->ops_user, cache);

    res = check_replay(cache);
    if (res != 0)
        return res;

    res = op_list_reserve(&cache->ops_group, 1);
    if (res != 0)
        return res;
    res = op_list_reserve(&cache->ops_user, 1);
    if (res != 0)
        return res;

    keyref.p = key;
    obj.key = &keyref;
    o = &obj;

    res = avl_tree_search(cache->cache, &o, &o);
    if (res != 0) {
        if (res != 1)
            return res;
        assert(CACHE_OBJ_VALID(o));
        if (o->deleted)
            return -EADDRNOTAVAIL;
        in_cache = 1;
    }

    /* delete from back end */
    res = (*(cache->ops->delete))(cache->ctx, key);
    if (res != 0)
        return res;

    trans_state = cache->trans_state;

    if (trans_state && in_cache) {
        /* delete from cache */
        o->deleted = 1;

        /* add delete operation to appropriate operation lists */
        if (trans_state & TRANS)
            op_list_add(&cache->ops_group, TRANS, DELETE, o);
        if (trans_state & USER_TRANS)
            op_list_add(&cache->ops_user, USER_TRANS, DELETE, o);
    }

    check_consistency(cache);
    return 0;
}

static int
fuse_cache_walk(void *ctx, back_end_walk_cb_t fn, void *wctx)
{
    avl_tree_iter_t citer;
    int res;
    size_t datalen, datasize;
    struct cache_obj *o;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;
    void *biter;
    void *iter;
    void *data;
    void *key, *minkey;

    /* allocate key and data buffers */

    key = do_malloc(cache->key_size);
    if (key == NULL)
        return -errno;

    datasize = 16;
    data = do_malloc(datasize);
    if (data == NULL) {
        res = -errno;
        goto err1;
    }
    datalen = 0;

    /* initialize cache and back end iterators */

    res = avl_tree_iter_new(&citer, cache->cache);
    if (res != 0) {
        if (res != -ENOENT)
            goto err2;
        citer = NULL;
    } else
        assert(citer != NULL);

    res = (*(cache->ops->iter_new))(&biter, cache->ctx);
    if (res != 0) {
        if (res != -ENOENT)
            goto err3;
        if (citer == NULL)
            return -ENOENT;
        biter = NULL;
    } else
        assert(biter != NULL);

    /* get minimum element */
    if (citer != NULL) {
        res = avl_tree_iter_get(citer, &o);
        if (res != 0)
            goto err4;
        if (biter == NULL) {
            iter = citer;
            minkey = (void *)(o->key->p);
        }
    }
    if (biter != NULL) {
        res = (*(cache->ops->iter_get))(biter, key, NULL, NULL);
        if (res != 0)
            goto err4;
        if (citer == NULL) {
            iter = biter;
            minkey = key;
        }
    }
    if ((citer != NULL) && (biter != NULL)) {
        res = get_next_iter_elem(o, key, &data, &datalen, &datasize, citer,
                                 &biter, &iter, &minkey, cache);
        if (res != 0)
            goto err4;
    }

    /* iterate through remaining elements */
    for (;;) {
        const void *d;
        int del;
        size_t dlen;

        /* invoke callback function with key and data of current minimum
           element */
        if (iter == biter) {
            res = do_iter_get(biter, minkey, &data, &datalen, &datasize, cache);
            if (res != 0)
                goto err4;
            d = data;
            dlen = datalen;
            del = 0;
        } else {
            d = o->data->p;
            dlen = o->datasize;
            del = o->deleted;
        }
        if (!del) {
            res = (*fn)(minkey, d, dlen, wctx);
            if (res != 0)
                goto err4;
        }

        /* advance iterator associated with current element */
        if (iter == citer) {
            res = avl_tree_iter_next(citer);
            if (res != 0) {
                if (res != -EADDRNOTAVAIL)
                    goto err4;
                avl_tree_iter_free(citer);
                citer = NULL;
                if (biter == NULL)
                    break;
                iter = biter;
            }
        } else {
            res = (*(cache->ops->iter_next))(biter);
            if (res != 0) {
                if (res != -EADDRNOTAVAIL)
                    goto err4;
                (*(cache->ops->iter_free))(biter);
                biter = NULL;
                if (citer == NULL)
                    break;
                iter = citer;
            }
        }

        /* get element at new iterator position */
        if (iter == citer) {
            res = avl_tree_iter_get(citer, &o);
            if (res != 0)
                goto err4;
            if (biter == NULL)
                minkey = (void *)(o->key->p);
        } else {
            res = (*(cache->ops->iter_get))(biter, key, NULL, NULL);
            if (res != 0)
                goto err4;
            if (citer == NULL)
                minkey = key;
        }

        if ((citer != NULL) && (biter != NULL)) { /* determine next element */
            res = get_next_iter_elem(o, key, &data, &datalen, &datasize, citer,
                                     &biter, &iter, &minkey, cache);
            if (res != 0)
                goto err4;
        }
    }

    free(key);
    free(data);

    return 0;

err4:
    if (biter != NULL)
        (*(cache->ops->iter_free))(biter);
err3:
    if (citer != NULL)
        avl_tree_iter_free(citer);
err2:
    free(data);
err1:
    free(key);
    return res;
}

static int
fuse_cache_iter_new(void **iter, void *ctx)
{
    int res;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;
    struct fuse_cache_iter *ret;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    ret->cache = cache;

    ret->key = do_malloc(cache->key_size);
    if (ret->key == NULL) {
        res = -errno;
        goto err1;
    }

    res = avl_tree_iter_new(&ret->citer, cache->cache);
    if (res != 0) {
        if (res != -ENOENT)
            goto err2;
        ret->citer = NULL;
    }

    res = (*(cache->ops->iter_new))(&ret->biter, cache->ctx);
    if (res != 0) {
        if (res != -ENOENT)
            goto err3;
        if (ret->citer == NULL) {
            res = -ENOENT;
            goto err3;
        }
        ret->biter = NULL;
    }

    ret->minkey = NULL;

    /* determine iterator referencing minimum element */
    if (ret->citer == NULL)
        ret->iter = ret->biter;
    else if (ret->biter == NULL)
        ret->iter = ret->citer;
    else {
        res = avl_tree_iter_get(ret->citer, &ret->o);
        if (res != 0)
            goto err4;
        res = (*(cache->ops->iter_get))(ret->biter, ret->key, NULL, NULL);
        if (res != 0)
            goto err4;

        res = get_next_iter_elem(ret->o, ret->key, NULL, NULL, NULL, ret->citer,
                                 &ret->biter, &ret->iter, &ret->minkey, cache);
        if (res != 0)
            goto err4;
    }

    *iter = ret;
    return 0;

err4:
    if (ret->biter != NULL)
        (*(cache->ops->iter_free))(ret->biter);
err3:
    if (ret->citer != NULL)
        avl_tree_iter_free(ret->citer);
err2:
    free(ret->key);
err1:
    free(ret);
    return res;
}

static int
fuse_cache_iter_free(void *iter)
{
    int err = 0, tmp;
    struct fuse_cache_iter *iterator = (struct fuse_cache_iter *)iter;

    if (iterator->citer != NULL)
        err = avl_tree_iter_free(iterator->citer);

    if (iterator->biter != NULL) {
        tmp = (*(iterator->cache->ops->iter_free))(iterator->biter);
        if (tmp != 0)
            err = tmp;
    }

    free(iterator->key);

    free(iterator);

    return err;
}

static int
fuse_cache_iter_get(void *iter, void *retkey, void *retdata,
                    size_t *retdatasize)
{
    int err;
    struct fuse_cache_iter *iterator = (struct fuse_cache_iter *)iter;

    if (iterator->minkey == NULL) {
        /* get element at new iterator position */
        if (iterator->iter == iterator->citer) {
            err = avl_tree_iter_get(iterator->citer, &iterator->o);
            if (err)
                return err;
            if (iterator->biter == NULL)
                iterator->minkey = (void *)(iterator->o->key->p);
        } else {
            err = (*(iterator->cache->ops->iter_get))(iterator->biter,
                                                      iterator->key, NULL,
                                                      NULL);
            if (err)
                return err;
            if (iterator->citer == NULL)
                iterator->minkey = iterator->key;
        }

        if ((iterator->citer != NULL) && (iterator->biter != NULL)) {
            /* determine next element */
            err = get_next_iter_elem(iterator->o, iterator->key, NULL, NULL,
                                     NULL, iterator->citer, &iterator->biter,
                                     &iterator->iter, &iterator->minkey,
                                     iterator->cache);
            if (err) {
                iterator->minkey = NULL;
                return err;
            }
        }
    }

    if (iterator->iter == iterator->citer) {
        struct cache_obj *o;

        avl_tree_iter_get(iterator->citer, &o);

        if (retkey != NULL)
            memcpy(retkey, o->key->p, iterator->cache->key_size);
        if (retdata != NULL)
            memcpy(retdata, o->data->p, o->datasize);
        if (retdatasize != NULL)
            *retdatasize = o->datasize;

        return 0;
    }

    /* iterator->iter == iterator->biter */

    return (*(iterator->cache->ops->iter_get))(iterator->iter, retkey, retdata,
                                               retdatasize);
}

static int
fuse_cache_iter_next(void *iter)
{
    int err;
    struct fuse_cache_iter *iterator = (struct fuse_cache_iter *)iter;

    /* advance iterator associated with current element */
    if (iterator->iter == iterator->citer) {
        for (;;) {
            struct cache_obj *o;

            err = avl_tree_iter_next(iterator->citer);
            if (err)
                break;

            err = avl_tree_iter_get(iterator->citer, &o);
            if (err || !(o->deleted))
                break;
        }
        if (err != -EADDRNOTAVAIL)
            return err;
        avl_tree_iter_free(iterator->citer);
        iterator->citer = NULL;
        if (iterator->biter == NULL)
            return -EADDRNOTAVAIL;
        iterator->iter = iterator->biter;
    } else {
        err = (*(iterator->cache->ops->iter_next))(iterator->biter);
        if (err) {
            if (err != -EADDRNOTAVAIL)
                return err;
            (*(iterator->cache->ops->iter_free))(iterator->biter);
            iterator->biter = NULL;
            if (iterator->citer == NULL)
                return -EADDRNOTAVAIL;
            iterator->iter = iterator->citer;
        }
    }

    return 0;
}

static int
fuse_cache_iter_search(void *iter, const void *key)
{
    avl_tree_iter_t citer;
    int res;
    struct fuse_cache_iter *iterator = (struct fuse_cache_iter *)iter;
    void *biter;

    res = avl_tree_iter_new(&citer, iterator->cache->cache);
    if (res != 0) {
        if (res != -ENOENT)
            return res;
        citer = NULL;
    }

    res = (*(iterator->cache->ops->iter_new))(&biter, iterator->cache->ctx);
    if (res != 0) {
        if (res != -ENOENT)
            goto err1;
        if (citer == NULL)
            return -ENOENT;
        biter = NULL;
    }

    if (citer != NULL) { /* look up in cache */
        res = do_iter_search_cache(citer, key, iterator->cache);
        if (res != 0)
            goto err2;
    }

    if (biter != NULL) { /* look up in back end */
        res = do_iter_search_be(biter, key, iterator->cache);
        if (res != 0)
            goto err2;
    }

    /* determine iterator referencing minimum element */
    if (citer == NULL)
        iterator->iter = biter;
    else if (biter == NULL)
        iterator->iter = citer;
    else {
        res = avl_tree_iter_get(citer, &iterator->o);
        if (res != 0)
            goto err2;
        res = (*(iterator->cache->ops->iter_get))(biter, iterator->key, NULL,
                                                  NULL);
        if (res != 0)
            goto err2;

        res = get_next_iter_elem(iterator->o, iterator->key, NULL, NULL, NULL,
                                 citer, &biter, &iterator->iter,
                                 &iterator->minkey, iterator->cache);
        if (res != 0)
            goto err2;
    }

    if (iterator->citer != NULL)
        avl_tree_iter_free(iterator->citer);
    iterator->citer = citer;
    if (iterator->biter != NULL)
        (*(iterator->cache->ops->iter_free))(iterator->biter);
    iterator->biter = biter;

    return 0;

err2:
    if (biter != NULL)
        (*(iterator->cache->ops->iter_free))(biter);
err1:
    if (citer != NULL)
        avl_tree_iter_free(citer);
    return res;
}

static int
fuse_cache_trans_new(void *ctx)
{
    int err;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    op_list_dump(stderr, &cache->ops_group, cache);
    op_list_dump(stderr, &cache->ops_user, cache);

    err = check_replay(cache);
    if (err)
        return err;

    err = (*(cache->ops->trans_new))(cache->ctx);
    if (err)
        return err;

    check_consistency(cache);

    return 0;
}

static int
fuse_cache_trans_abort(void *ctx)
{
    int err;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    op_list_dump(stderr, &cache->ops_group, cache);
    op_list_dump(stderr, &cache->ops_user, cache);

    err = check_replay(cache);
    if (err)
        return err;

    err = (*(cache->ops->trans_abort))(cache->ctx);
    if (err)
        return err;

    check_consistency(cache);

    return 0;
}

static int
fuse_cache_trans_commit(void *ctx)
{
    int err;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    op_list_dump(stderr, &cache->ops_group, cache);
    op_list_dump(stderr, &cache->ops_user, cache);

    err = check_replay(cache);
    if (err)
        return err;

    err = (*(cache->ops->trans_commit))(cache->ctx);
    if (err)
        return err;

    check_consistency(cache);

    return 0;
}

static int
fuse_cache_sync(void *ctx)
{
    int err;
    struct fuse_cache *cache = (struct fuse_cache *)ctx;

    op_list_dump(stderr, &cache->ops_group, cache);
    op_list_dump(stderr, &cache->ops_user, cache);

    err = check_replay(cache);
    if (err)
        return err;

    err = (*(cache->ops->sync))(cache->ctx);
    if (err)
        return err;

    check_consistency(cache);

    return 0;
}

void
fuse_cache_set_dump_cb(struct fuse_cache *cache,
                       void (*cb)(FILE *, const void *, const void *, size_t,
                                  const char *, void *),
                       void *ctx)
{
    cache->dump_cb = cb;
    cache->dump_ctx = (cb == NULL) ? NULL : ctx;
}

/* vi: set expandtab sw=4 ts=4: */
