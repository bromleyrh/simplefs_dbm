#
# ax_func_error.m4
#

# FIXME: refactor the following

AC_DEFUN([DEF_HAVE_ERROR],
    AC_DEFINE(
        [HAVE_ERROR],
        [1],
        [Define to 1 if you have the `error` function.]
    )
)

AC_DEFUN([DEF_HAVE_ERRC],
    AC_DEFINE(
        [HAVE_ERRC],
        [1],
        [Define to 1 if you have the `errc` function.]
    )
)

AC_DEFUN([DEF_HAVE_WARNC],
    AC_DEFINE(
        [HAVE_WARNC],
        [1],
        [Define to 1 if you have the `warnc` function.]
    )
)

AC_DEFUN([AX_FUNC_ERROR],
    [AC_CACHE_CHECK(
        [for error],
        [ax_cv_have_error],
        [AC_LINK_IFELSE(
            [AC_LANG_PROGRAM(
                [#include <error.h>],
                [error(0, 1, "%s", "Error");]
             )
            ],
            [ax_cv_have_error=yes],
            [ax_cv_have_error=no]
         )
        ]
     )
     AS_IF(
        [test $ax_cv_have_error = "no"],
        [AC_CACHE_CHECK(
            [for errc and warnc],
            [ax_cv_have_errc_warnc],
            [AC_LINK_IFELSE(
                [AC_LANG_PROGRAM(
                    [#include <err.h>],
                    [errc(0, 1, "%s", "Error"); warnc(1, "%s", "Warning");]
                 )
                ],
                [ax_cv_have_errc_warnc=yes],
                [ax_cv_have_errc_warnc=no]
             )
            ]
         )
        ]
     )
     AS_IF(
        [test $ax_cv_have_error = "yes"],
        [DEF_HAVE_ERROR],
        [test $ax_cv_have_errc_warnc = "yes"],
        [DEF_HAVE_ERRC
         DEF_HAVE_WARNC]
     )
    ]
)

# vi: set expandtab sw=4 ts=4:
