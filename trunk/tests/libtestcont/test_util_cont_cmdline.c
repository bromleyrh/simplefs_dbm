/*
 * test_util_cont_cmdline.c
 */

#include "test_util_cont.h"
#include "test_util_cont_cmdline.h"

#define NO_ASSERT
#include "common.h"
#undef NO_ASSERT

#include <test_util.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char *
cont_test_usage(const char *progusage, int order_stats)
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
        "    -t         do not maintain container (see -b, -r, and -n "
        "options)\n"
        "    -v         verify container against bitmap periodically\n"
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
cont_test_opt_str(const char *test_opt_str, int order_stats)
{
    static char buf[512];

    static const char std_opt_str[] = "bcdFi:k:Mn:P:p:Stvw:";
    static const char order_stats_opt_str[] = "O";

    snprintf(buf, sizeof(buf), "%s%s%s", std_opt_str,
             order_stats ? order_stats_opt_str : "", test_opt_str);

    return buf;
}

int
parse_cont_test_opt(int opt, void *test_opts)
{
    struct cont_params *contp;
    struct cont_test_opts *testopts = (struct cont_test_opts *)test_opts;

    contp = testopts->contp;

    switch (opt) {
    case 'b':
        contp->use_bitmap = 0;
        break;
    case 'c':
        contp->confirm = 1;
        break;
    case 'd':
        contp->dump = 1;
        *verbose_debug = 1;
        break;
    case 'F':
        *fault_test = 1;
        break;
    case 'i':
        contp->insert_ratio = atoi(optarg);
        break;
    case 'k':
        contp->max_key = atoi(optarg);
        break;
    case 'M':
        *mem_test = 1;
        break;
    case 'n':
        contp->num_ops = strtoull(optarg, NULL, 10);
        break;
    case 'O':
        if (testopts->order_stats)
            contp->test_order_stats = 1;
        break;
    case 'P':
        contp->verification_period = atoi(optarg);
        break;
    case 'p':
        contp->search_period = atoi(optarg);
        break;
    case 'S':
        contp->verbose_stats = 1;
        break;
    case 't':
        contp->use_cont = 0;
        break;
    case 'v':
        contp->verify = 1;
        break;
    case 'w':
        contp->key_size = 4 * atoi(optarg);
        break;
    default:
        return (*(testopts->parse_test_opt))(opt, testopts->test_opts);
    }

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
