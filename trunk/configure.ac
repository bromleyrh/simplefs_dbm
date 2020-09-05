#
# configure.ac
#

env_cflags="$CFLAGS"

AC_INIT([simplefs], m4_esyscmd_s([cat .version]))
AC_PREREQ([2.69])

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

AC_CHECK_HEADERS([linux/fs.h linux/magic.h sys/xattr.h])

AC_CHECK_TYPES([clockid_t], [], [],
               [
               #include <time.h>
               ]
               )

AC_CHECK_MEMBERS([struct stat.st_atimespec, struct stat.st_mtimespec,
                  struct stat.st_ctimespec])

AC_CHECK_FUNCS([fdatasync posix_fallocate])

AX_FUNC_ERROR

AC_ARG_WITH([libfuse-3],
            [  --with-libfuse-3        use libfuse 3],
            [case "$withval" in
                 yes)
                     libfuse3=true;;
                 no)
                     libfuse3=false;;
                 *)
                     AC_MSG_ERROR([invalid "--with-libfuse-3" argument]);;
             esac],
            [libfuse3=false])
AM_CONDITIONAL([LIBFUSE_3], [test x$libfuse3 = xtrue])

if test x$platform = xdarwin; then
    fusepkg=osxfuse
elif test x$libfuse3 = xtrue; then
    fusepkg=fuse3
else
    fusepkg=fuse
fi

fuse_cppflags=`eval $pkgcfg --cflags $fusepkg 2>/dev/null`
libjson_cppflags=`eval $pkgcfg --cflags libjson`
libtest_cppflags=`eval $pkgcfg --cflags libtest`
libutil_cppflags=`eval $pkgcfg --cflags libutil`

fuse_link_dep=`eval $pkgcfg --libs $fusepkg 2>/dev/null`
libjson_link_dep=`eval $pkgcfg --libs libjson`
libtest_link_dep=`eval $pkgcfg --libs libtest`
libutil_link_dep=`eval $pkgcfg --libs libutil`

AC_SUBST([fuse_cppflags])
AC_SUBST([libjson_cppflags])
AC_SUBST([libtest_cppflags])
AC_SUBST([libutil_cppflags])

AC_SUBST([fuse_link_dep])
AC_SUBST([libjson_link_dep])
AC_SUBST([libtest_link_dep])
AC_SUBST([libutil_link_dep])

req_priv="libjson libutil"
AC_SUBST([req_priv])

AC_ARG_ENABLE([sanitizers],
              [  --enable-sanitizers     enable GCC sanitizers],
              [case "$enableval" in
                   yes)
                       sanitizers=true;;
                   no)
                       sanitizers=false;;
                   *)
                       AC_MSG_ERROR([invalid "--enable-sanitizers" argument]);;
               esac],
              [sanitizers=false])

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

if test "x$sanitizers" = xtrue; then
    AX_GCC_SANITIZERS
    sanitizer=$ax_cv_gcc_sanitizers
fi
AM_CONDITIONAL([SANITIZERS], [test x$sanitizers = xtrue])
AC_SUBST([sanitizer])

AC_ARG_WITH([pkgconfigdir],
            [  --with-pkgconfigdir=DIR install pkg-config data in DIR],
            [pkgconfigdir="$withval"],
            [pkgconfigdir="$libdir/pkgconfig"])
AC_SUBST([pkgconfigdir])

dnl FIXME: Later, only prevent Autoconf from adding "-g -O2" to CFLAGS
CFLAGS="$env_cflags"

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT

cat <<- EOF

$PACKAGE_NAME configuration

               Compiler: $CC

              Debugging: $debug
         GCC sanitizers: $sanitizers

    Installation prefix: $prefix

EOF

dnl vi: set expandtab sw=4 ts=4:
