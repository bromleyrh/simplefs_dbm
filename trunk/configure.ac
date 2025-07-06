#
# configure.ac
#

AC_INIT([simplefs], m4_esyscmd_s([cat .version]))
AC_PREREQ([2.69])

env_cflags=$CFLAGS

AC_CONFIG_SRCDIR([simplefs.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET

dnl ensure installed files are accessible by non-root users when parent
dnl directories are created
dnl FIXME: Honor file mode creation mask for non-installation directories
MKDIR_P="build-aux/mkpath -m 0755"

AM_INIT_AUTOMAKE([foreign no-define subdir-objects])
AM_SILENT_RULES([yes])
LT_INIT([disable-static])

AS_CASE(
    [$target_os],
        [*darwin*],
            [platform=darwin],
        [*freebsd*],
            [platform=freebsd],
        [*linux*],
            [platform=linux],
        [AC_MSG_ERROR([unsupported platform], [1])]
)
AM_CONDITIONAL([APPLE], [test $platform = "darwin"])
AM_CONDITIONAL([FREEBSD], [test $platform = "freebsd"])
AM_CONDITIONAL([LINUX], [test $platform = "linux"])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB

AC_CHECK_PROGS([pkgcfg], [pkg-config pkgconf])

AM_CONDITIONAL([CLANG], [test "x$CC" = "xclang"])
AM_CONDITIONAL([GCC], [test "x$CC" = "xgcc"])

std_cppflags="-D_XOPEN_SOURCE=700"
AC_SUBST([std_cppflags])

AX_CHECK_COMPILE_FLAG([-std=c11], [std_flags="-std=c11"], [std_flags=])
AC_SUBST([std_flags])

warnings="-Wstrict-aliasing"

AX_CHECK_COMPILE_FLAG(
    [-Werror -Wgnu-include-next -Wnewline-eof -Wnullability-extension],
    [warnings="$warnings -Wpedantic -Wno-gnu-include-next -Wno-newline-eof"
     warnings="$warnings -Wno-nullability-extension"]
)

AC_SUBST([warnings])

AX_CHECK_COMPILE_FLAG([-Werror -fstack-protector-all],
    [stack_protector="-fstack-protector-all"],
    [stack_protector=]
)
AC_SUBST([stack_protector])

AX_CHECK_COMPILE_FLAG([-Werror -fstrict-aliasing],
    [strict_aliasing="-fstrict-aliasing"],
    [strict_aliasing=]
)
AC_SUBST([strict_aliasing])

AC_CHECK_HEADERS([linux/fs.h linux/magic.h sys/xattr.h])

AM_CONDITIONAL([HAVE_LINUX_FS_H],
               [test "x$ac_cv_header_linux_fs_h" = "xyes"])

AC_CHECK_TYPES([clockid_t], [], [],
               [
#include <time.h>
]
)

old_cflags=$CFLAGS
CFLAGS="$CFLAGS $std_cppflags"
AC_CHECK_MEMBERS([struct stat.st_atimensec, struct stat.st_mtimensec,
                  struct stat.st_ctimensec])
AC_CHECK_MEMBERS([struct stat.st_atim, struct stat.st_mtim,
                  struct stat.st_ctim])
AC_CHECK_MEMBERS([struct stat.st_atimespec, struct stat.st_mtimespec,
                  struct stat.st_ctimespec])
CFLAGS=$old_cflags

AC_CHECK_FUNCS([posix_fallocate])

AX_FUNC_ERROR
AX_FUNC_FCNTL

AC_ARG_WITH([libfuse-3],
            [  --with-libfuse-3        use libfuse 3],
            [AS_CASE(
                [$withval],
                    [yes],
                        [libfuse3=true],
                    [no],
                        [libfuse3=false],
                    [AC_MSG_ERROR([invalid "--with-libfuse-3" argument])]
             )
            ],
            [libfuse3=false])
AM_CONDITIONAL([LIBFUSE_3], [test $libfuse3 = true])

AS_IF(
    [test $platform = "darwin"],
    [fusepkg=osxfuse],
    [test $libfuse3 = true],
    [fusepkg=fuse3],
    [fusepkg=fuse]
)

fuse_cppflags=`eval $pkgcfg --cflags $fusepkg 2>/dev/null`
libjson_cppflags=`eval $pkgcfg --cflags libjson`
libn_cppflags=`eval $pkgcfg --cflags libn`
libtest_cppflags=`eval $pkgcfg --cflags libtest`
libutil_cppflags=`eval $pkgcfg --cflags libutil`

fuse_link_dep=`eval $pkgcfg --libs $fusepkg 2>/dev/null`
libjson_link_dep=`eval $pkgcfg --libs libjson`
libn_link_dep=`eval $pkgcfg --libs libn`
libtest_link_dep=`eval $pkgcfg --libs libtest`
libutil_link_dep=`eval $pkgcfg --libs libutil`

AC_SUBST([fuse_cppflags])
AC_SUBST([libjson_cppflags])
AC_SUBST([libn_cppflags])
AC_SUBST([libtest_cppflags])
AC_SUBST([libutil_cppflags])

AC_SUBST([fuse_link_dep])
AC_SUBST([libjson_link_dep])
AC_SUBST([libn_link_dep])
AC_SUBST([libtest_link_dep])
AC_SUBST([libutil_link_dep])

AC_ARG_ENABLE([sanitizers],
              [  --enable-sanitizers     enable GCC sanitizers],
              [AS_CASE(
                  [$enableval],
                      [yes],
                          [sanitizers=true],
                      [no],
                          [sanitizers=false],
                      [AC_MSG_ERROR([invalid "--enable-sanitizers" argument])]
               )
              ],
              [sanitizers=false])

AC_ARG_ENABLE([debugging],
              [  --enable-debugging      enable debugging],
              [AS_CASE(
                  [$enableval],
                      [yes],
                          [debug=true],
                      [no],
                          [debug=false],
                      [AC_MSG_ERROR([invalid "--enable-debugging" argument])]
               )
              ],
              [debug=false])
AM_CONDITIONAL([DEBUG], [test $debug = true])

AC_ARG_ENABLE([assertions],
              [  --enable-assertions     enable debugging assertions],
              [AS_CASE(
                  [$enableval],
                      [yes],
                          [assertions=true],
                      [no],
                          [assertions=false],
                      [AC_MSG_ERROR([invalid "--enable-assertions" argument])]
               )
              ],
              [assertions=false])
AM_CONDITIONAL([ASSERTIONS], [test x$assertions = xtrue])

AC_ARG_ENABLE([coverage_analysis],
              [  --enable-coverage-analysis
                          enable code coverage analysis],
              [AS_CASE(
                  [$enableval],
                      [yes],
                          [coverage_analysis=true],
                      [no],
                          [coverage_analysis=false],
                      [AC_MSG_ERROR(
                          [invalid "--enable-coverage-analysis" argument]
                       )
                      ]
               )
              ],
              [coverage_analysis=false])
AM_CONDITIONAL([COVERAGE_ANALYSIS], [test $coverage_analysis = true])

AS_IF(
    [test $sanitizers = true],
    [AX_GCC_SANITIZERS
     sanitizer=$ax_cv_gcc_sanitizers]
)
AM_CONDITIONAL([SANITIZERS], [test $sanitizers = true])
AC_SUBST([sanitizer])

AC_ARG_WITH([pkgconfigdir],
            [  --with-pkgconfigdir=DIR install pkg-config data in DIR],
            [pkgconfigdir=$withval],
            [pkgconfigdir="$libdir/pkgconfig"])
AC_SUBST([pkgconfigdir])

dnl FIXME: Later, only prevent Autoconf from adding "-g -O2" to CFLAGS
CFLAGS=$env_cflags

AC_CONFIG_FILES([Makefile man/Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT

cat <<-EOF

$PACKAGE_NAME configuration

               Compiler: $CC

              Debugging: $debug
         GCC sanitizers: $sanitizers
      Coverage analysis: $coverage_analysis

    Installation prefix: $prefix

EOF

dnl vi: set expandtab sw=4 ts=4:
