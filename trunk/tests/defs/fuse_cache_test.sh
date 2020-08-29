#!/bin/sh

exec $TESTDIR/fuse_cache_test -n 4096 -P 128 -v
