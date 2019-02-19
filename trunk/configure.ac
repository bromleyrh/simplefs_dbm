#
# configure.ac
#

AC_INIT([simplefs], m4_esyscmd_s([cat .version]))
AC_PREREQ([2.69])

AC_CONFIG_SRCDIR([simplefs.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([foreign no-define subdir-objects])
AM_SILENT_RULES([yes])
LT_INIT([disable-static])

case $target_os in
    *darwin*)
        platform=darwin;;
    *freebsd*)
        platform=freebsd;;
    *linux*)
        platform=linux;;
    *)
        AC_MSG_ERROR([unsupported platform], [1]);;
esac
AM_CONDITIONAL([APPLE], [test "x$platform" = "xdarwin"])
AM_CONDITIONAL([LINUX], [test "x$platform" = "xlinux"])

CFLAGS=""

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB

AC_CHECK_PROGS([pkgcfg], [pkg-config pkgconf])

AM_CONDITIONAL([CLANG], [test "x$CC" = "xclang"])
AM_CONDITIONAL([GCC], [test "x$CC" = "xgcc"])

AX_CHECK_COMPILE_FLAG([-Werror -fstack-protector-all],
    [stack_protector="-fstack-protector-all"],
    [stack_protector=""]
)
AC_SUBST([stack_protector])

AX_FUNC_ERROR

fuse_cppflags=`eval $pkgcfg --cflags fuse 2>/dev/null`
libutil_cppflags=`eval $pkgcfg --cflags libutil`

fuse_link_dep=`eval $pkgcfg --libs fuse 2>/dev/null`
libutil_link_dep=`eval $pkgcfg --libs libutil`

AC_SUBST([fuse_cppflags])
AC_SUBST([libjson_cppflags])
AC_SUBST([libutil_cppflags])

AC_SUBST([fuse_link_dep])
AC_SUBST([libjson_link_dep])
AC_SUBST([libutil_link_dep])

req_priv="libjson libutil"
AC_SUBST([req_priv])

AC_ARG_ENABLE([debugging],
              [  --enable-debugging      enable debugging],
              [case "$enableval" in
                   yes)
                       debug=true;;
                   no)
                       debug=false;;
                   *)
                       AC_MSG_ERROR([invalid "--enable-debugging" argument]);;
               esac],
              [debug=false])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])

AC_ARG_ENABLE([assertions],
              [  --enable-assertions     enable debugging assertions],
              [case "$enableval" in
                   yes)
                       assertions=true;;
                   no)
                       assertions=false;;
                   *)
                       AC_MSG_ERROR([invalid "--enable-assertions" argument]);;
               esac],
              [assertions=false])
AM_CONDITIONAL([ASSERTIONS], [test x$assertions = xtrue])

AC_ARG_WITH([pkgconfigdir],
            [  --with-pkgconfigdir=DIR install pkg-config data in DIR],
            [pkgconfigdir="$withval"],
            [pkgconfigdir="$libdir/pkgconfig"])
AC_SUBST([pkgconfigdir])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT

cat <<- EOF

$PACKAGE_NAME configuration

               Compiler: $CC

              Debugging: $debug

    Installation prefix: $prefix

EOF

dnl vi: set expandtab sw=4 ts=4:
