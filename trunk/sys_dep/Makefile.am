##
## Makefile.am
##

noinst_HEADERS += sys_dep/sys_dep.h

noinst_LIBRARIES += sys_dep/libsys.a

generic_sources :=
platform_sources :=

sys_dep_libsys_a_CPPFLAGS = $(AM_CPPFLAGS) -Isys_dep
sys_dep_libsys_a_CFLAGS = $(AM_CFLAGS)

if LINUX
platform_sources += sys_dep/linux/blk_get_size.c
if HAVE_LINUX_FS_H
sys_dep_cppflags += -DSYS_DEP_BLK_GET_SIZE
endif
else
if FREEBSD
platform_sources += sys_dep/freebsd/blk_get_size.c
sys_dep_cppflags += -DSYS_DEP_BLK_GET_SIZE
else
if APPLE
platform_sources += sys_dep/darwin/blk_get_size.c
sys_dep_cppflags += -DSYS_DEP_BLK_GET_SIZE
else
generic_sources += sys_dep/generic/blk_get_size.c
endif
endif
endif

if LINUX
platform_sources += sys_dep/linux/fcntl_ofd_setlk.c
else
generic_sources += sys_dep/generic/fcntl_ofd_setlk.c
endif

generic_sources += sys_dep/generic/file_lock.c

sys_dep_libsys_a_SOURCES = $(generic_sources) $(platform_sources)

## vi: set noexpandtab sw=4 ts=4:
