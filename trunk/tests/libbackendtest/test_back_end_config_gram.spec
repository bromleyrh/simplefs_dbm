#
# test_back_end_config_gram.spec
#

<config> = {
    <iter_test_period?>
    <iter_test_out_of_range_period?>
    <out_of_range_period?>
    <purge_factor?>
    <purge_interval?>
    <purge_period?>
    <sorted_test_period?>
}

<iter_test_period>
    = "iter_test_period"              : <number> # default: 1024

<iter_test_out_of_range_period>
    = "iter_test_out_of_range_period" : <number> # default: 16 * 1024

<out_of_range_period>
    = "out_of_range_period"           : <number> # default: 16 * 1024

<purge_factor>
    = "purge_factor"                  : <number> # default: 8

<purge_interval>
    = "purge_interval"                : <number> # default: 8 * 1024 * 1024

<purge_period>
    = "purge_period"                  : <number> # default: 1024 * 1024

<sorted_test_period>
    = "sorted_test_period"            : <number> # default: 4 * 1024

# vi: set expandtab sw=4 ts=4:
