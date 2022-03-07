/*
 * test_util_back_end_cmdline.c
 */

#include "test_util_back_end.h"
#include "test_util_back_end_cmdline.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <test_util.h>

#include <strings_ext.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char *
be_test_usage(const char *progusage, int order_stats)
{
    size_t i;
    size_t len;
    static char buf[2048];

    static const char *const std_usage[] = {
        "    -b         do not maintain verification bitmap (see -t, -r, and "
        "-n options)\n"
        "    -c         confirm every insertion and deletion with a search\n"
        "    -d         enable debugging output\n"
        "    -F         enable operation errors having probability "
        "1/(1024*1024)\n"
        "    -i INTEGER use given insertion ratio\n"
        "    -k INTEGER use given maximum key value\n"
        "    -M         generate malloc() errors with probability "
        "1/(1024*1024)\n"
        "    -n INTEGER stop after given number of operations\n",
        "    -P INTEGER if -v given, verify against bitmap every N operations\n"
        "    -p INTEGER perform search every N operations\n"
        "    -S         output statistics continuously to standard error\n"
        "    -t         do not maintain back end (see -b, -r, and -n "
        "options)\n"
        "    -v         verify back end against bitmap periodically\n"
        "    -w INTEGER use given key size in 4-byte words\n"
    };

    static const char order_stats_usage[] =
        "    -O         additionally test select and get index operations\n";

    len = 0;
    for (i = 0; i < ARRAY_SIZE(std_usage); i++) {
        int tmp, tmplen;

        tmplen = sizeof(buf) - len;
        tmp = snprintf(buf + len, tmplen, "%s", std_usage[i]);
        if (tmp >= tmplen)
            goto end;

        len += tmp;
    }

    snprintf(buf + len, sizeof(buf) - len, "%s\n%s",
             order_stats ? order_stats_usage : "", progusage);

end:
    return buf;
}

const char *
be_test_opt_str(const char *test_opt_str, int order_stats)
{
    static char buf[512];

    static const char std_opt_str[] = "bcdFi:k:Mn:P:p:Stvw:";
    static const char order_stats_opt_str[] = "O";

    fillbuf(buf, "%s%s%s", std_opt_str, order_stats ? order_stats_opt_str : "",
            test_opt_str);

    return buf;
}

int
parse_be_test_opt(int opt, void *test_opts)
{
    struct be_params *bep;
    struct be_test_opts *testopts = (struct be_test_opts *)test_opts;

    bep = testopts->bep;

    switch (opt) {
    case 'b':
        bep->use_bitmap = 0;
        break;
    case 'c':
        bep->confirm = 1;
        break;
    case 'd':
        bep->dump = 1;
        *verbose_debug = 1;
        break;
    case 'F':
        *fault_test = 1;
        break;
    case 'i':
        bep->insert_ratio = atoi(optarg);
        break;
    case 'k':
        bep->max_key = atoi(optarg);
        break;
    case 'M':
        *mem_test = 1;
        break;
    case 'n':
        bep->num_ops = strtoull(optarg, NULL, 10);
        break;
    case 'O':
        if (testopts->order_stats)
            bep->test_order_stats = 1;
        break;
    case 'P':
        bep->verification_period = atoi(optarg);
        break;
    case 'p':
        bep->search_period = atoi(optarg);
        break;
    case 'S':
        bep->verbose_stats = 1;
        break;
    case 't':
        bep->use_be = 0;
        break;
    case 'v':
        bep->verify = 1;
        break;
    case 'w':
        bep->key_size = 4 * atoi(optarg);
        break;
    default:
        return (*testopts->parse_test_opt)(opt, testopts->test_opts);
    }

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
