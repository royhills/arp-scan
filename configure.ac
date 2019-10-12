dnl Process this file with autoconf to produce a configure script.

AC_INIT([arp-scan],[1.9.6],[https://github.com/royhills/arp-scan])
AC_PREREQ(2.61)
AC_REVISION($Revision$)
AC_CONFIG_SRCDIR([arp-scan.c])
AM_INIT_AUTOMAKE

AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST

dnl Define the appropriate compiler flags if the user has enabled gcov
dnl code coverage. We do this before calling AC_PROG_CC because we override
dnl the default compiler options when running with gcov.
AC_MSG_CHECKING([if gcov code coverage is enabled])
AC_ARG_ENABLE(gcov,
   AS_HELP_STRING([--enable-gcov],[enable gcov code coverage analysis]),
   [
      if test "x$enableval" != "xno" ; then
         AC_MSG_RESULT(yes)
         CFLAGS="-O0 -g -fno-inline -fprofile-arcs -ftest-coverage"
      else
         AC_MSG_RESULT(no)
      fi
   ],
   [
      AC_MSG_RESULT(no)
   ] )
dnl Checks for programs.
AC_PROG_CC
if test -n "$GCC"; then
   AC_DEFINE([ATTRIBUTE_UNUSED], [__attribute__ ((__unused__))],
             [Define to the compiler's unused pragma])
   CFLAGS="$CFLAGS -Wall -Wshadow -Wwrite-strings"
   GCC_WEXTRA
   GCC_STACK_PROTECT_CC
   GCC_FORTIFY_SOURCE
   GCC_FORMAT_SECURITY
dnl Uncomment the line below to compile with additional warnings enabled.
dnl CFLAGS="$CFLAGS -pedantic -Wpointer-arith -Wcast-qual -Wcast-align -Wconversion -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wnested-externs"
else
   AC_DEFINE([ATTRIBUTE_UNUSED], [],
             [Define to the compiler's unused pragma])
fi
AC_PROG_INSTALL
AC_PROG_LN_S

dnl Checks for libraries.
dnl Solaris 10 needs nsl and socket.  Linux and {Free,Open}BSD do not.
dnl Just about everything will need pcap.
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([pcap_open_live], [pcap], ,
   [
   AC_MSG_NOTICE([Cannot find pcap library containing pcap_open_live])
   AC_MSG_ERROR([Check that you have libpcap version 1.5 or later installed])
   ])

dnl Check that the pcap library contains pcap_set_immediate_mode()
dnl This was introduced in libpcap version 1.5, and our application requires it.
dnl
dnl We perform this check as a seperate step, rather than just checking for
dnl pcap_lib_version in the earlier AC_SEARCH_LIBS call, because it
dnl allows us to provide different error messages for missing pcap and non
dnl functional pcap and so avoids confusing generic error messages.
dnl
AC_MSG_CHECKING([for a compatible pcap library])
AC_LINK_IFELSE([AC_LANG_CALL([], [pcap_set_immediate_mode])],
   [AC_MSG_RESULT([yes])],
   [
   AC_MSG_RESULT([no])
   AC_MSG_NOTICE([Cannot find pcap_set_immediate_mode in pcap library])
   AC_MSG_ERROR([Check that the pcap library is at least version 1.5])
   ])

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h sys/socket.h sys/time.h unistd.h getopt.h pcap.h sys/ioctl.h sys/stat.h fcntl.h search.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl Check for the uint{8,16,32}_t types and, if we don't have them, define
dnl them using types which will work on most systems.
AC_NTA_CHECK_TYPE(uint8_t, unsigned char)
AC_NTA_CHECK_TYPE(uint16_t, unsigned short)
AC_NTA_CHECK_TYPE(uint32_t, unsigned int)

dnl Checks for 64-bit integer types.  These checks are from postgresql.
dnl Check to see if we have a working 64-bit integer type.
dnl This breaks down into two steps:
dnl (1) figure out if the compiler has a 64-bit int type with working
dnl arithmetic, and if so
dnl (2) see whether snprintf() can format the type correctly.

PGAC_TYPE_64BIT_INT([long int])

if test x"$HAVE_LONG_INT_64" = x"yes" ; then
  INT64_TYPE="long int"
  UINT64_TYPE="unsigned long int"
else
  PGAC_TYPE_64BIT_INT([long long int])
    if test x"$HAVE_LONG_LONG_INT_64" = x"yes" ; then
      INT64_TYPE="long long int"
      UINT64_TYPE="unsigned long long int"
    else
      AC_MSG_ERROR([cannot determine 64-bit integer type])
    fi
fi

AC_DEFINE_UNQUOTED(ARP_INT64, $INT64_TYPE,
                   [Define to the appropriate type for 64-bit ints.])
AC_DEFINE_UNQUOTED(ARP_UINT64, $UINT64_TYPE,
                   [Define to the appropriate type for unsigned 64-bit ints.])

dnl If we found "long int" is 64 bits, assume snprintf handles it.  If
dnl we found we need to use "long long int", better check.  We cope with
dnl snprintfs that use %lld, %qd, or %I64d as the format.
dnl
if test "$HAVE_LONG_LONG_INT_64" = yes ; then
  PGAC_FUNC_SNPRINTF_LONG_LONG_INT_FORMAT
  if test "$LONG_LONG_INT_FORMAT" = ""; then
    AC_MSG_ERROR([cannot determine snprintf format string for long long int])
  fi
  LONG_LONG_UINT_FORMAT=`echo "$LONG_LONG_INT_FORMAT" | sed 's/d$/u/'`
  INT64_FORMAT="\"$LONG_LONG_INT_FORMAT\""
  UINT64_FORMAT="\"$LONG_LONG_UINT_FORMAT\""
else
  # Here if we are not using 'long long int' at all
  INT64_FORMAT='"%ld"'
  UINT64_FORMAT='"%lu"'
fi

AC_DEFINE_UNQUOTED(ARP_INT64_FORMAT, $INT64_FORMAT,
                   [Define to the appropriate snprintf format for 64-bit ints.])

AC_DEFINE_UNQUOTED(ARP_UINT64_FORMAT, $UINT64_FORMAT,
                   [Define to the appropriate snprintf format for unsigned 64-bit ints.])

dnl Checks for library functions.
AC_CHECK_FUNCS([malloc gethostbyname gettimeofday inet_ntoa memset select socket strerror])

dnl Check if the Posix regular expression functions "regcomp" and "regexec"
dnl and the header file "regex.h" are present.
AC_MSG_CHECKING([for posix regular expression support])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <regex.h>]],
[[regcomp(0, 0, 0);
regexec(0, 0, 0, 0, 0)]])],
[ac_nta_posix_regex=yes],
[ac_nta_posic_regex=no])
AC_MSG_RESULT([$ac_nta_posix_regex])
if test $ac_nta_posix_regex = no; then
   AC_MSG_ERROR([You don't seem to have posix regular expression support])
else
   AC_DEFINE(HAVE_REGEX_H, 1, [Define to 1 if you have posix regex support])
fi

dnl Determine which link-layer sending functions to use
dnl We base our choice on the operating system in $host_os
case $host_os in
   *linux* )
      AC_MSG_NOTICE([Using packet socket link layer implementation.]);
      AC_CHECK_HEADERS([netpacket/packet.h net/if.h])
      AC_LIBOBJ([link-packet-socket])
      ;;
   *freebsd* | *darwin* | *openbsd* | *netbsd* | *dragonfly* )
      AC_MSG_NOTICE([Using BPF link layer implementation.]);
dnl We need to specify additional headers to include here, because several
dnl BSD variants require certain headers to be included before others will
dnl work.
dnl FreeBSD 5.2 needs sys/socket.h included for net/if, and
dnl needs sys/types.h for sys/sysctl.h and net/bpf.h
dnl OpenBSD 3.9 needs sys/param.h included for sys/sysctl.h
      AC_CHECK_HEADERS([net/if.h sys/param.h sys/sysctl.h net/route.h net/if_dl.h],,,
      [
      #include <sys/types.h>
      #ifdef HAVE_SYS_SOCKET_H
      #include <sys/socket.h>
      #endif
      #ifdef HAVE_SYS_PARAM_H
      #include <sys/param.h>
      #endif
      ])
      AC_LIBOBJ([link-bpf])
      ;;
   *solaris* )
      AC_MSG_NOTICE([Using DLPI link layer implementation.]);
dnl Solaris 9 needs sys/types.h and sys/socket.h included before net/if.h.
      AC_CHECK_HEADERS([sys/dlpi.h sys/dlpihdr.h stropts.h sys/ioctl.h sys/sockio.h net/if.h sys/bufmod.h],,,
      [
      #include <sys/types.h>
      #ifdef HAVE_SYS_SOCKET_H
      #include <sys/socket.h>
      #endif
      ])
      AC_LIBOBJ([link-dlpi])
      ;;
dnl   *cygwin* )
   * )
      AC_MSG_ERROR([Host operating system $host_os is not supported])
      ;;
esac

dnl Linux and most BSD systems have getopt_long_only, but NetBSD 7.0 doesn't.
dnl For systems that don't have it, use the GNU getopt sources from glibc.
AC_CHECK_FUNC([getopt_long_only], ,
  [ AC_LIBOBJ(getopt)
    AC_LIBOBJ(getopt1)
    AC_LIBSOURCE(getopt.h) ])

dnl Check for strlcat and strlcpy.  If we don't have them, use the replacement
dnl functions from OpenBSD.  Most modern C libraries have these functions,
dnl but some such as as glibc don't.
AC_CHECK_FUNC([strlcat],
              [AC_DEFINE(HAVE_STRLCAT, 1, [Define to 1 if the C library includes the strlcat function])],
              [AC_LIBOBJ(strlcat)])
AC_CHECK_FUNC([strlcpy],
              [AC_DEFINE(HAVE_STRLCPY, 1, [Define to 1 if the C library includes the strlcpy function])],
              [AC_LIBOBJ(strlcpy)])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
