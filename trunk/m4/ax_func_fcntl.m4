#
# ax_func_fcntl.m4
#

AC_DEFUN([AX_FUNC_FCNTL],
    [AC_CACHE_CHECK(
        [if fcntl(F_OFD_*) supported],
        [ax_cv_have_fcntl_f_ofd_locks],
        [AC_RUN_IFELSE(
            [AC_LANG_PROGRAM([
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdlib.h>
#include <unistd.h>
], [
char template[[]] = _PATH_TMP "ax_fcntl_f_ofd_locks_XXXXXX";
int fd, ret;
struct flock lk = {
    .l_type     = F_WRLCK,
    .l_whence   = SEEK_SET
};

fd = mkstemp(template);
if (fd == -1)
    return EXIT_FAILURE;

ret = fcntl(fd, F_OFD_SETLK, &lk);
if (ret == -1)
    ret = errno;

close(fd);
unlink(template);

return ret == 0 || ret == EAGAIN ? EXIT_SUCCESS : EXIT_FAILURE;
]            )
            ],
            [ax_cv_have_fcntl_f_ofd_locks=yes],
            [ax_cv_have_fcntl_f_ofd_locks=no]
         )
        ]
     )
     AS_IF(
        [test $ax_cv_have_fcntl_f_ofd_locks = yes],
        [AC_DEFINE(
            [HAVE_FCNTL_F_OFD_LOCKS],
            [1],
            [Define to 1 if the F_OFD_SETLK, F_OFD_SETLKW, and F_OFD_GETLK
             `fcntl' operations are supported.]
         )
        ]
     )
    ]
)

# vi: set expandtab sw=4 ts=4:
