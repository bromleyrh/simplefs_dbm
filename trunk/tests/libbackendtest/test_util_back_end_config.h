/*
 * test_util_back_end_config.h
 */

#ifndef _TEST_UTIL_BACK_END_CONFIG_H
#define _TEST_UTIL_BACK_END_CONFIG_H

#include <stdio.h>

struct params {
    int iter_test_period;
    int iter_test_out_of_range_period;
    int out_of_range_period;
    int purge_factor;
    int purge_interval;
    int purge_period;
    int sorted_test_period;
};

int parse_config(const char *path, struct params *params);

void print_config(FILE *f, const struct params *params);

#endif

/* vi: set expandtab sw=4 ts=4: */
