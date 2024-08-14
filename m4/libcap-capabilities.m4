dnl Check for POSIX.1e capabilities support with libcap
AC_DEFUN([CHECK_LIBCAP],
[
  AC_ARG_WITH(libcap,
    AS_HELP_STRING([--with-libcap@<:@=auto/yes/no@:>@],[Build with libcap POSIX.1e capabilities support @<:@default=auto@:>@]),,
    with_libcap=auto)

  if test "X$with_libcap" = "Xno" ; then
      have_libcap=no;
  else
      # Check for header file
      AC_CHECK_HEADER(sys/capability.h, cap_headers=yes, cap_headers=no)
      # Check for library
      AC_CHECK_LIB(cap, cap_set_proc, cap_library=yes, cap_library=no)
      # Check results are usable
      if test "X$with_libcap" = "Xyes" -a "X$cap_library" = "Xno" ; then
         AC_MSG_ERROR([libcap support was requested but the library was not found])
      fi
      if test "X$cap_library" = "Xyes" -a "X$cap_headers" = "Xno" ; then
         AC_MSG_ERROR([libcap libraries found but headers are missing])
      fi
  fi
  AC_MSG_CHECKING([whether to use libcap])
  if test "X$cap_library" = "Xyes" -a "X$cap_library" = "Xyes"; then
      AC_DEFINE(HAVE_LIBCAP,1,[Define to 1 if you have the libcap library])
      AC_DEFINE(HAVE_SYS_CAPABILITY_H,1,[Define to 1 if you have the <sys/capability.h> header file])
      LIBS="-lcap $LIBS"
      AC_MSG_RESULT([yes])
      AC_MSG_NOTICE([Including libcap POSIX.1e capability support])
  else
      AC_MSG_RESULT([no])
      AC_MSG_NOTICE([POSIX.1e capabilities disabled or not supported])
  fi
])
