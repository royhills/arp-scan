dnl autoconf macros

dnl
dnl Useful macros for autoconf to check for ssp-patched gcc
dnl 1.0 - September 2003 - Tiago Sousa <mirage@kaotik.org>
dnl
dnl Modified by ffontaine pull request: use AC_LINK_IFELSE instead of
dnl AC_COMPILE_IFELSE because some systems may be missing the libssp library
dnl even though the compiler accepts the option.
dnl
dnl About ssp:
dnl GCC extension for protecting applications from stack-smashing attacks
dnl http://www.research.ibm.com/trl/projects/security/ssp/
dnl
dnl Usage:
dnl After calling the correct AC_LANG_*, use the corresponding macro:
dnl
dnl GCC_STACK_PROTECT_CC
dnl checks -fstack-protector with the C compiler, if it exists then updates
dnl CFLAGS and defines ENABLE_SSP_CC
dnl
dnl GCC_STACK_PROTECT_CXX
dnl checks -fstack-protector with the C++ compiler, if it exists then updates
dnl CXXFLAGS and defines ENABLE_SSP_CXX
dnl
AC_DEFUN([GCC_STACK_PROTECT_CC],[
  ssp_cc=yes
  if test "X$CC" != "X"; then
    AC_MSG_CHECKING([whether ${CC} accepts -fstack-protector])
    ssp_old_cflags="$CFLAGS"
    CFLAGS="$CFLAGS -fstack-protector"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[],[ssp_cc=no])
    echo $ssp_cc
    if test "X$ssp_cc" = "Xno"; then
      CFLAGS="$ssp_old_cflags"
    else
      AC_DEFINE([ENABLE_SSP_CC], 1, [Define if SSP C support is enabled.])
    fi
  fi
])

AC_DEFUN([GCC_STACK_PROTECT_CXX],[
  ssp_cxx=yes
  if test "X$CXX" != "X"; then
    AC_MSG_CHECKING([whether ${CXX} accepts -fstack-protector])
    ssp_old_cxxflags="$CXXFLAGS"
    CXXFLAGS="$CXXFLAGS -fstack-protector"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[],[ssp_cxx=no])
    echo $ssp_cxx
    if test "X$ssp_cxx" = "Xno"; then
        CXXFLAGS="$ssp_old_cxxflags"
    else
      AC_DEFINE([ENABLE_SSP_CXX], 1, [Define if SSP C++ support is enabled.])
    fi
  fi
])

dnl Check whether GCC accepts -D_FORTIFY_SOURCE
dnl
dnl This was introduced in GCC 4.1 and glibc 2.4, but was present in earlier
dnl versions on redhat systems (specifically GCC 3.4.3 and above).
dnl
dnl We define the GNUC_PREREQ macro to the same definition as __GNUC_PREREQ
dnl in <features.h>. We don't use __GNUC_PREREQ directly because <features.h>
dnl is not present on all the operating systems that we support, e.g. OpenBSD.
dnl
AC_DEFUN([GCC_FORTIFY_SOURCE],[
   if test "X$CC" != "X"; then
      AC_MSG_CHECKING([whether ${CC} accepts -D_FORTIFY_SOURCE])
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[
         #define GNUC_PREREQ(maj, min) ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
         #if !(GNUC_PREREQ (4, 1) \
            || (defined __GNUC_RH_RELEASE__ && GNUC_PREREQ (4, 0)) \
            || (defined __GNUC_RH_RELEASE__ && GNUC_PREREQ (3, 4) \
               && __GNUC_MINOR__ == 4 \
               && (__GNUC_PATCHLEVEL__ > 2 \
                  || (__GNUC_PATCHLEVEL__ == 2 && __GNUC_RH_RELEASE__ >= 8))))
         #error No FORTIFY_SOURCE support
         #endif
      ]])],[
         AC_MSG_RESULT(yes)
         CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2"
      ],[
         AC_MSG_RESULT(no)
      ])
   fi
])

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

dnl Check for libcap POSIX capabilities support
AC_DEFUN([CHECK_LIBCAP],
[
  AC_ARG_WITH(libcap,
    AS_HELP_STRING([--with-libcap=@<:@auto/yes/no@:>@],[Add Libcap support @<:@default=auto@:>@]),,
    with_libcap=auto)

  if test x$with_libcap = xno ; then
      have_libcap=no;
  else
      # Check for header file
      AC_CHECK_HEADER(sys/capability.h, cap_headers=yes, cap_headers=no)
      # Check for library
      AC_CHECK_LIB(cap, cap_set_proc, cap_library=yes, cap_library=no)
      # Check results are usable
      if test x$with_libcap = xyes -a x$cap_library = xno ; then
         AC_MSG_ERROR(libcap support was requested but the library was not found)
      fi
      if test x$cap_library = xyes -a x$cap_headers = xno ; then
         AC_MSG_ERROR(libcap libraries found but headers are missing)
      fi
  fi
  AC_MSG_CHECKING(whether to use libcap)
  if test x$cap_library = xyes -a x$cap_library = xyes; then
      AC_DEFINE(HAVE_LIBCAP,1,[Define to 1 if you have the libcap library])
      AC_DEFINE(HAVE_SYS_CAPABILITY_H,1,[Define to 1 if you have the <sys/capability.h> header file])
      LIBS="-lcap $LIBS"
      AC_MSG_RESULT(yes)
  else
      AC_MSG_RESULT(no)
  fi
])
