dnl Process this file with autoconf to produce a configure script.

AC_INIT([arp-scan],[1.9.8],[https://github.com/royhills/arp-scan])
AC_PREREQ([2.61])
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

dnl Checks for libraries.
dnl Solaris 10 needs -lnsl for gethostbyname() and -lsocket for socket().
dnl Linux, {Free,Open,Net,Dragonfly}BSD and MacOS X do not.
dnl Just about everything will need -lpcap for pcap_open_live().
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
dnl We perform this check as a separate step, rather than just checking for
dnl pcap_lib_version in the earlier AC_SEARCH_LIBS call, because it
dnl allows us to provide different error messages for missing pcap and non
dnl functional pcap and so avoids confusing generic error messages.
dnl
AC_MSG_CHECKING([for a compatible pcap library with pcap_set_immediate_mode])
AC_LINK_IFELSE([AC_LANG_CALL([], [pcap_set_immediate_mode])],
   [AC_MSG_RESULT([yes])],
   [
   AC_MSG_RESULT([no])
   AC_MSG_NOTICE([Cannot find pcap_set_immediate_mode in pcap library])
   AC_MSG_ERROR([Check that the pcap library is at least version 1.5])
   ])

dnl Checks for header files.

dnl Check for C POSIX library header files
dnl Are all valid targets POSIX compliant?  If so, do we need to check these?
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h sys/socket.h sys/time.h unistd.h sys/stat.h fcntl.h search.h regex.h])

dnl Check for other required header files
AC_CHECK_HEADERS([getopt.h pcap.h sys/ioctl.h ifaddrs.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

dnl Checks for library functions.
dnl All of these are defined by POSIX
AC_CHECK_FUNCS([malloc gethostbyname gettimeofday inet_ntoa memset select socket strerror])
dnl These functions might not be present on all systems
AC_CHECK_FUNCS([getifaddrs])

dnl Determine which link-layer implementation to use
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
