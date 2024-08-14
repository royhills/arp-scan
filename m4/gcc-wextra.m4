dnl Check for support of the GCC -Wextra option, which enables extra warnings.
dnl Support for this option was added in gcc 3.4.0.
dnl
AC_DEFUN([GCC_WEXTRA],[
  gcc_wextra=yes
  if test "X$CC" != "X"; then
    AC_MSG_CHECKING([whether ${CC} accepts -Wextra])
    gcc_old_cflags="$CFLAGS"
    CFLAGS="$CFLAGS -Wextra"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[
       AC_MSG_RESULT(yes)
    ],[
       AC_MSG_RESULT(no)
       gcc_wextra=no
       CFLAGS="$ssp_old_cflags"
    ])
  fi
])
