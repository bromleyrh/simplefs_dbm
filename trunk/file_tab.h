/*
 * file_tab.h
 */

#ifndef _FILE_TAB_H
#define _FILE_TAB_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct file_tab;

int file_tab_init(struct file_tab **tab);

void file_tab_destroy(struct file_tab *tab);

int file_tab_get(struct file_tab *tab, void *data, uint64_t *res);

void *file_tab_look_up(struct file_tab *tab, uint64_t desc);

void file_tab_put(struct file_tab *tab, uint64_t desc);

int file_tab_dump(FILE *f, struct file_tab *ftab);

#endif

/* vi: set expandtab sw=4 ts=4: */
