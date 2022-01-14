#
# ax_gcc_sanitizers.m4
#

AC_DEFUN([AX_GCC_SANITIZERS],
    [AC_MSG_CHECKING([for GCC sanitizer flags])
     ax_cv_gcc_sanitizers_cached=true
     AC_CACHE_VAL([ax_cv_gcc_sanitizers],
        [AS_ECHO([])
         ax_cv_gcc_sanitizers_cached=false
         AC_CHECK_LIB([asan], [__interceptor_malloc], [asan_libs="-lasan"])
         AC_CHECK_LIB([ubsan], [__ubsan_handle_add_overflow],
             [ubsan_libs="-lubsan"])

         fsanitizer="-fsanitize=address -fsanitize=undefined"
         fsanitizer="$fsanitizer -fsanitize-undefined-trap-on-error"
         AX_CHECK_COMPILE_FLAG([-fsanitize=address],
             [ax_cv_gcc_sanitizers=$fsanitizer],
             [ax_cv_gcc_sanitizers=]
         )
         AS_IF(
            [test "x$asan_libs" = x || test "x$ubsan_libs" = x],
            [ax_cv_gcc_sanitizers=]
         )
        ]
     )
     AS_IF(
        [test $ax_cv_gcc_sanitizers_cached = true],
        [AS_ECHO([])]
     )
    ]
)

# vi: set expandtab sw=4 ts=4:
