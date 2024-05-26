/*
 * test_util_back_end_config.c
 */

#include "test_back_end_config_gram_spec.h"
#include "test_util_back_end_config.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <io_ext.h>

#include <json/filters.h>
#include <json/grammar.h>
#include <json/grammar_parse.h>
#include <json/native.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#define ROOT_RULE_ID "config"

static size_t read_cb(char *, size_t, size_t, void *);

static int u64_to_int_filter(void *, void *, void *);

static size_t
read_cb(char *buf, size_t off, size_t len, void *ctx)
{
    FILE *f = ctx;
    size_t ret;

    (void)off;

    ret = fread(buf, 1, len, f);
    return ret == 0 && !feof(f) ? (size_t)-1 : ret;
}

static int
u64_to_int_filter(void *src, void *dst, void *arg)
{
    (void)arg;

    *(int *)dst = *(uint64_t *)src;
    return 0;
}

#define SCAN_SPEC(param) \
    {L"" STR(param), JSON_TYPE_NUMBER, 0, 0, 0, &u64_to_int_filter, NULL, \
     NULL, offsetof(struct params, param)}

int
parse_config(const char *path, struct params *params)
{
    int err;
    FILE *f;
    json_value_t jval;
    struct json_parser *parser;
    struct json_in_filter_ctx rctx;

    static const struct json_scan_spec spec[] = {
        SCAN_SPEC(iter_test_period),
        SCAN_SPEC(iter_test_out_of_range_period),
        SCAN_SPEC(out_of_range_period),
        SCAN_SPEC(purge_factor),
        SCAN_SPEC(purge_interval),
        SCAN_SPEC(purge_period),
        SCAN_SPEC(sorted_test_period)
    };

    f = fopen_flags(path, "r", FOPEN_CLOEXEC | FOPEN_NOCTTY);
    if (f == NULL)
        return -errno;

    err = json_parser_init(BACK_END_TEST_CONFIG_GRAM, ROOT_RULE_ID, &parser);
    if (err) {
        fclose(f);
        return err;
    }

    json_read_cb_ctx_init(&rctx);
    rctx.read_cb = &read_cb;
    rctx.ctx = f;

    err = json_grammar_validate(NULL, &json_read_cb_strip_comments, &rctx,
                                parser, &jval);

    json_parser_destroy(parser);

    fclose(f);

    if (!err) {
        if (json_val_object_get_num_elem(jval) > 0)
            err = json_oscanf(params, spec, ARRAY_SIZE(spec), 0, jval);
        json_val_free(jval);
    }

    return err;
}

#undef SCAN_SPEC

void
print_config(FILE *f, const struct params *params)
{
    fprintf(f,
            "             iter_test_period: %d\n"
            "iter_test_out_of_range_period: %d\n"
            "          out_of_range_period: %d\n"
            "                 purge_factor: %d\n"
            "               purge_interval: %d\n"
            "                 purge_period: %d\n"
            "           sorted_test_period: %d\n",
            params->iter_test_period,
            params->iter_test_out_of_range_period,
            params->out_of_range_period,
            params->purge_factor,
            params->purge_interval,
            params->purge_period,
            params->sorted_test_period);
}

/* vi: set expandtab sw=4 ts=4: */
