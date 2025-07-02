##
## Makefile.am
##

noinst_HEADERS += sys_dep/sys_dep.h

noinst_LIBRARIES += sys_dep/libsys.a

sys_dep_libsys_a_CPPFLAGS = $(AM_CPPFLAGS) -Isys_dep
sys_dep_libsys_a_CFLAGS = $(AM_CFLAGS)

if LINUX
sys_dep_libsys_a_SOURCES = sys_dep/linux/blk_get_size.c
if HAVE_LINUX_FS_H
sys_dep_cppflags += -DSYS_DEP_BLK_GET_SIZE
endif
else
if FREEBSD
sys_dep_libsys_a_SOURCES = sys_dep/freebsd/blk_get_size.c
sys_dep_cppflags += -DSYS_DEP_BLK_GET_SIZE
else
if APPLE
sys_dep_libsys_a_SOURCES = sys_dep/darwin/blk_get_size.c
sys_dep_cppflags += -DSYS_DEP_BLK_GET_SIZE
else
sys_dep_libsys_a_SOURCES = sys_dep/generic/blk_get_size.c
endif
endif
endif

if LINUX
sys_dep_libsys_a_SOURCES += sys_dep/linux/fcntl_ofd_setlk.c
else
sys_dep_libsys_a_SOURCES += sys_dep/generic/fcntl_ofd_setlk.c
endif

sys_dep_libsys_a_SOURCES += sys_dep/generic/file_lock.c

## vi: set noexpandtab sw=4 ts=4:
