/*
 * file_tab.c
 */

#include "common.h"
#include "file_tab.h"
#include "util.h"

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct file_tab_list_head {
    void    *baseptr;
    size_t  entsize;
    size_t  head;
};

struct file_tab_list_entry {
    size_t next;
};

struct file_tab {
    struct file_tab_list_head   head;
    size_t                      len;
    size_t                      sz;
    pthread_mutex_t             mtx;
};

union file_tab_ent {
    struct file_tab_list_entry  ent;
    void                        *data;
};

#define FILE_TAB_LIST_SUBSCRIPT(list, idx) \
    (struct file_tab_list_entry *)((char *)(list)->baseptr \
                                   + ((idx) - 1) * (list)->entsize)

#define FILE_TAB_LIST_NEW(list, basep, entsz) \
    do { \
        (list)->head = 0; \
        (list)->baseptr = basep; \
        (list)->entsize = entsz; \
    } while (0)

#define FILE_TAB_LIST_INSERT(list, prev_ent, ent) \
    do { \
        size_t next_ent; \
        struct file_tab_list_entry *entptr, *tmp; \
        \
        if ((prev_ent) == 0) { \
            next_ent = (list)->head; \
            (list)->head = (ent); \
        } else { \
            tmp = FILE_TAB_LIST_SUBSCRIPT(list, prev_ent); \
            next_ent = tmp->next; \
            tmp->next = (ent); \
        } \
        entptr = FILE_TAB_LIST_SUBSCRIPT(list, ent); \
        entptr->next = next_ent; \
    } while (0)

#define FILE_TAB_LIST_REMOVE_FIRST(list) \
    do { \
        struct file_tab_list_entry *entptr; \
        \
        entptr = FILE_TAB_LIST_SUBSCRIPT(list, (list)->head); \
        (list)->head = entptr->next; \
    } while (0)

int
file_tab_init(struct file_tab **tab)
{
    int err;
    struct file_tab *ret;
    union file_tab_ent *baseptr;

    if (oemalloc(&ret) == NULL)
        return MINUS_ERRNO;

    err = pthread_mutex_init(&ret->mtx, NULL);
    if (err)
        goto err1;

    ret->sz = 16;
    if (oeallocarray(&baseptr, ret->sz) == NULL) {
        err = MINUS_ERRNO;
        goto err2;
    }
    ret->len = 0;

    FILE_TAB_LIST_NEW(&ret->head, baseptr, sizeof(*baseptr));

    *tab = ret;
    return 0;

err2:
    pthread_mutex_destroy(&ret->mtx);
err1:
    free(ret);
    return err;
}

void
file_tab_destroy(struct file_tab *tab)
{
    free(tab->head.baseptr);
    pthread_mutex_destroy(&tab->mtx);
}

int
file_tab_get(struct file_tab *tab, void *data, uint64_t *res)
{
    int err;
    size_t first;
    uint64_t ret;
    union file_tab_ent *ent;

    pthread_mutex_lock(&tab->mtx);

    first = tab->head.head;
    if (first == 0) {
        if (tab->len == tab->sz) {
            size_t newsz;
            union file_tab_ent *tmp;

            newsz = 2 * tab->sz;
            if (oereallocarray(tab->head.baseptr, &tmp, newsz) == NULL) {
                err = MINUS_ERRNO;
                pthread_mutex_unlock(&tab->mtx);
                return err;
            }
            tab->head.baseptr = tmp;
            tab->sz = newsz;
        }
        ret = ++tab->len;
    } else {
        FILE_TAB_LIST_REMOVE_FIRST(&tab->head);
        ret = first;
    }

    ent = (union file_tab_ent *)FILE_TAB_LIST_SUBSCRIPT(&tab->head, ret);
    ent->data = data;

    pthread_mutex_unlock(&tab->mtx);

    *res = ret - 1;
    return 0;
}

void *
file_tab_look_up(struct file_tab *tab, uint64_t desc)
{
    union file_tab_ent *ent;
    void *ret;

    pthread_mutex_lock(&tab->mtx);
    ent = (union file_tab_ent *)FILE_TAB_LIST_SUBSCRIPT(&tab->head, desc + 1);
    ret = ent->data;
    pthread_mutex_unlock(&tab->mtx);

    return ret;
}

void
file_tab_put(struct file_tab *tab, uint64_t desc)
{
    pthread_mutex_lock(&tab->mtx);
    FILE_TAB_LIST_INSERT(&tab->head, 0, desc + 1);
    pthread_mutex_unlock(&tab->mtx);
}

int
file_tab_dump(FILE *f, struct file_tab *tab)
{
    size_t cur, next;

    for (cur = tab->head.head; cur != 0; cur = next) {
        union file_tab_ent *ent;

        ent = (union file_tab_ent *)FILE_TAB_LIST_SUBSCRIPT(&tab->head, cur);

        if (fprintf(f, "%zu: %zu\n", cur, ent->ent.next) < 0)
            return -EIO;

        next = ent->ent.next;
    }

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
