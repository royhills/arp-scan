dnl Check for support of the GCC -Wformat-security option.
dnl This option was introduced in GCC 3.0.
dnl
dnl Note that in this test, the test compilation fails if the option is
dnl supported, and succeeds if it is not supported.
dnl
dnl If this option is supported, then the test program will produce a
dnl warning like "format not a string literal and no format arguments".
dnl If it is not supported, then the test program will compile without
dnl warnings.
dnl
AC_DEFUN([GCC_FORMAT_SECURITY],[
   if test "X$CC" != "X"; then
      AC_MSG_CHECKING([whether ${CC} accepts -Wformat-security])
      wfs_old_cflags="$CFLAGS"
      CFLAGS="$CFLAGS -Wall -Werror -Wformat -Wformat-security"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>]], [[
         char *fmt=NULL;
         printf(fmt);
         return 0;
      ]])],[
         AC_MSG_RESULT(no)
         CFLAGS="$wfs_old_cflags"
      ],[
         AC_MSG_RESULT(yes)
         CFLAGS="$wfs_old_cflags -Wformat -Wformat-security"
      ])
   fi
])
