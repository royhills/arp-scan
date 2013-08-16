dnl NTA Monitor autoconf macros

dnl	AC_NTA_CHECK_TYPE -- See if a type exists using reasonable includes
dnl
dnl	Although there is a standard macro AC_CHECK_TYPE, we can't always
dnl	use this because it doesn't include enough header files.
dnl
AC_DEFUN([AC_NTA_CHECK_TYPE],
   [AC_MSG_CHECKING([for $1 using $CC])
   AC_CACHE_VAL(ac_cv_nta_have_$1,
	AC_TRY_COMPILE([
#	include "confdefs.h"
#	include <stdio.h>
#	if HAVE_SYS_TYPES_H
#	 include <sys/types.h>
#	endif
#	if HAVE_SYS_STAT_H
#	 include <sys/stat.h>
#	endif
#	ifdef STDC_HEADERS
#	 include <stdlib.h>
#	 include <stddef.h>
#	endif
#	if HAVE_INTTYPES_H
#	 include <inttypes.h>
#	else
#	 if HAVE_STDINT_H
#	  include <stdint.h>
#	 endif
#	endif
#	if HAVE_UNISTD_H
#	 include <unistd.h>
#	endif
#	ifdef HAVE_ARPA_INET_H
#	 include <arpa/inet.h>
#	endif
#	ifdef HAVE_NETDB_H
#	 include <netdb.h>
#	endif
#	ifdef HAVE_NETINET_IN_H
#	 include <netinet/in.h>
#	endif
#	ifdef SYS_SOCKET_H
#	 include <sys/socket.h>
#	endif
	],
	[$1 i],
	ac_cv_nta_have_$1=yes,
	ac_cv_nta_have_$1=no))
   AC_MSG_RESULT($ac_cv_nta_have_$1)
   if test $ac_cv_nta_have_$1 = no ; then
	   AC_DEFINE($1, $2, [Define to required type if we don't have $1])
   fi])

dnl	AC_NTA_NET_SIZE_T -- Determine type of 3rd argument to accept
dnl
dnl	This type is normally socklen_t but is sometimes size_t or int instead.
dnl	We try, in order: socklen_t, int, size_t until we find one that compiles
dnl
AC_DEFUN([AC_NTA_NET_SIZE_T],
   [AC_MSG_CHECKING([for socklen_t or equivalent using $CC])
   ac_nta_net_size_t=no
   AC_TRY_COMPILE([
#	include "confdefs.h"
#	include <sys/types.h>
#	ifdef HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#	endif],
	[int s;
	struct sockaddr addr;
	socklen_t addrlen;
	int result;
	result=accept(s, &addr, &addrlen)],
	   ac_nta_net_size_t=socklen_t,ac_nta_net_size_t=no)
   if test $ac_nta_net_size_t = no; then
   AC_TRY_COMPILE([
#	include "confdefs.h"
#	include <sys/types.h>
#	ifdef HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#	endif],
	[int s;
	struct sockaddr addr;
	int addrlen;
	int result;
	result=accept(s, &addr, &addrlen)],
	ac_nta_net_size_t=int,ac_nta_net_size_t=no)
   fi
   if test $ac_nta_net_size_t = no; then
   AC_TRY_COMPILE([
#	include "confdefs.h"
#	include <sys/types.h>
#	ifdef HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#	endif],
	[int s;
	struct sockaddr addr;
	size_t addrlen;
	int result;
	result=accept(s, &addr, &addrlen)],
	ac_nta_net_size_t=size_t,ac_nta_net_size_t=no)
   fi
   if test $ac_nta_net_size_t = no; then
      AC_MSG_ERROR([Cannot find acceptable type for 3rd arg to accept()])
   else
      AC_MSG_RESULT($ac_nta_net_size_t)
      AC_DEFINE_UNQUOTED(NET_SIZE_T, $ac_nta_net_size_t, [Define required type for 3rd arg to accept()])
   fi
   ])

dnl PGAC_TYPE_64BIT_INT(TYPE)
dnl -------------------------
dnl Check if TYPE is a working 64 bit integer type. Set HAVE_TYPE_64 to
dnl yes or no respectively, and define HAVE_TYPE_64 if yes.
dnl
dnl This function comes from the Postgresql file:
dnl pgsql/config/c-compiler.m4,v 1.13
dnl
AC_DEFUN([PGAC_TYPE_64BIT_INT],
[define([Ac_define], [translit([have_$1_64], [a-z *], [A-Z_P])])dnl
define([Ac_cachevar], [translit([pgac_cv_type_$1_64], [ *], [_p])])dnl
AC_CACHE_CHECK([whether $1 is 64 bits], [Ac_cachevar],
[AC_TRY_RUN(
[typedef $1 int64;

/*
 * These are globals to discourage the compiler from folding all the
 * arithmetic tests down to compile-time constants.
 */
int64 a = 20000001;
int64 b = 40000005;

int does_int64_work()
{
  int64 c,d;

  if (sizeof(int64) != 8)
    return 0;			/* definitely not the right size */

  /* Do perfunctory checks to see if 64-bit arithmetic seems to work */
  c = a * b;
  d = (c + b) / b;
  if (d != a+1)
    return 0;
  return 1;
}
main() {
  exit(! does_int64_work());
}],
[Ac_cachevar=yes],
[Ac_cachevar=no],
[# If cross-compiling, check the size reported by the compiler and
# trust that the arithmetic works.
AC_COMPILE_IFELSE([AC_LANG_BOOL_COMPILE_TRY([], [sizeof($1) == 8])],
                  Ac_cachevar=yes,
                  Ac_cachevar=no)])])

Ac_define=$Ac_cachevar
if test x"$Ac_cachevar" = xyes ; then
  AC_DEFINE(Ac_define,, [Define to 1 if `]$1[' works and is 64 bits.])
fi
undefine([Ac_define])dnl
undefine([Ac_cachevar])dnl
])# PGAC_TYPE_64BIT_INT

dnl PGAC_FUNC_SNPRINTF_LONG_LONG_INT_FORMAT
dnl ---------------------------------------
dnl Determine which format snprintf uses for long long int.  We handle
dnl %lld, %qd, %I64d.  The result is in shell variable
dnl LONG_LONG_INT_FORMAT.
dnl
dnl MinGW uses '%I64d', though gcc throws an warning with -Wall,
dnl while '%lld' doesn't generate a warning, but doesn't work.
dnl
dnl This function comes from the Postgresql file:
dnl pgsql/config/c-library.m4,v 1.28
dnl
AC_DEFUN([PGAC_FUNC_SNPRINTF_LONG_LONG_INT_FORMAT],
[AC_MSG_CHECKING([snprintf format for long long int])
AC_CACHE_VAL(pgac_cv_snprintf_long_long_int_format,
[for pgac_format in '%lld' '%qd' '%I64d'; do
AC_TRY_RUN([#include <stdio.h>
typedef long long int int64;
#define INT64_FORMAT "$pgac_format"

int64 a = 20000001;
int64 b = 40000005;

int does_int64_snprintf_work()
{
  int64 c;
  char buf[100];

  if (sizeof(int64) != 8)
    return 0;			/* doesn't look like the right size */

  c = a * b;
  snprintf(buf, 100, INT64_FORMAT, c);
  if (strcmp(buf, "800000140000005") != 0)
    return 0;			/* either multiply or snprintf is busted */
  return 1;
}
main() {
  exit(! does_int64_snprintf_work());
}],
[pgac_cv_snprintf_long_long_int_format=$pgac_format; break],
[],
[pgac_cv_snprintf_long_long_int_format=cross; break])
done])dnl AC_CACHE_VAL

LONG_LONG_INT_FORMAT=''

case $pgac_cv_snprintf_long_long_int_format in
  cross) AC_MSG_RESULT([cannot test (not on host machine)]);;
  ?*)    AC_MSG_RESULT([$pgac_cv_snprintf_long_long_int_format])
         LONG_LONG_INT_FORMAT=$pgac_cv_snprintf_long_long_int_format;;
  *)     AC_MSG_RESULT(none);;
esac])# PGAC_FUNC_SNPRINTF_LONG_LONG_INT_FORMAT

dnl
dnl Useful macros for autoconf to check for ssp-patched gcc
dnl 1.0 - September 2003 - Tiago Sousa <mirage@kaotik.org>
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
    AC_TRY_COMPILE(,,, ssp_cc=no)
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
    AC_TRY_COMPILE(,,, ssp_cxx=no)
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
   if test "x$CC" != "X"; then
      AC_MSG_CHECKING([whether ${CC} accepts -D_FORTIFY_SOURCE])
      AC_TRY_COMPILE(,[
         #define GNUC_PREREQ(maj, min) ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
         #if !(GNUC_PREREQ (4, 1) \
            || (defined __GNUC_RH_RELEASE__ && GNUC_PREREQ (4, 0)) \
            || (defined __GNUC_RH_RELEASE__ && GNUC_PREREQ (3, 4) \
               && __GNUC_MINOR__ == 4 \
               && (__GNUC_PATCHLEVEL__ > 2 \
                  || (__GNUC_PATCHLEVEL__ == 2 && __GNUC_RH_RELEASE__ >= 8))))
         #error No FORTIFY_SOURCE support
         #endif
      ], [
         AC_MSG_RESULT(yes)
         CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2"
      ], [
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
   if test "x$CC" != "X"; then
      AC_MSG_CHECKING([whether ${CC} accepts -Wformat-security])
      wfs_old_cflags="$CFLAGS"
      CFLAGS="$CFLAGS -Wall -Werror -Wformat -Wformat-security"
      AC_TRY_COMPILE([#include <stdio.h>], [
         char *fmt=NULL;
         printf(fmt);
         return 0;
      ], [
         AC_MSG_RESULT(no)
         CFLAGS="$wfs_old_cflags"
      ], [
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
    AC_TRY_COMPILE(,,[
       AC_MSG_RESULT(yes)
    ],[
       AC_MSG_RESULT(no)
       gcc_wextra=no
       CFLAGS="$ssp_old_cflags"
    ])
  fi
])
