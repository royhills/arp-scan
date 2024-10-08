# Process this file with autoconf to produce a configure script.

AC_INIT([arp-scan],[1.10.1-git],[https://github.com/royhills/arp-scan])
AC_PREREQ([2.70])
AC_CONFIG_SRCDIR([arp-scan.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE

AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST

# Define the appropriate compiler flags if the user has enabled gcov
# code coverage. We do this before calling AC_PROG_CC because we override
# the default compiler options when running with gcov.
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

# Check for utility programs that we need.
AC_PROG_SED
AC_PROG_CC
# Ensure the C compiler supports the C99 standard.
if test "x$ac_cv_prog_cc_c99" = "xno"; then
   AC_MSG_ERROR([C compiler does not support C99 standard])
fi
# Add additional options if the C compiler identifies as GCC.
# This applies to Clang/LLVM in addition to GCC.
if test -n "$GCC"; then
   AC_DEFINE([ATTRIBUTE_UNUSED], [__attribute__ ((__unused__))],
             [Define to the compiler's unused pragma])
   CFLAGS="$CFLAGS -Wall -Wextra -Wformat-security -Wshadow -Wwrite-strings"
   GCC_STACK_PROTECT_CC
   GCC_FORTIFY_SOURCE
# Uncomment the line below to compile with additional warnings enabled.
# CFLAGS="$CFLAGS -pedantic -Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wnested-externs"
else
   AC_DEFINE([ATTRIBUTE_UNUSED], [],
             [Define to the compiler's unused pragma])
fi
AC_PROG_INSTALL

# Checks for libraries.
# Only Solaris 10 needs -lnsl for gethostbyname() and -lsocket for socket().
# Everything needs -lpcap for pcap_open_live() and other functions.
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([pcap_open_live], [pcap], ,
   [
   AC_MSG_NOTICE([Cannot find pcap library containing pcap_open_live])
   AC_MSG_ERROR([Check that you have libpcap version 1.5 or later installed])
   ])

# Check that the pcap library contains pcap_set_immediate_mode()
# This was introduced in libpcap version 1.5, and the application requires it.
#
# We perform this check as a separate step, rather than just checking for
# pcap_lib_version in the earlier AC_SEARCH_LIBS call, because it
# allows us to provide different error messages for missing pcap and non
# functional pcap and so avoids confusing generic error messages.
#
AC_MSG_CHECKING([for a compatible pcap library with pcap_set_immediate_mode])
AC_LINK_IFELSE([AC_LANG_CALL([], [pcap_set_immediate_mode])],
   [AC_MSG_RESULT([yes])],
   [
   AC_MSG_RESULT([no])
   AC_MSG_NOTICE([Cannot find pcap_set_immediate_mode in pcap library])
   AC_MSG_ERROR([Check that the pcap library is at least version 1.5])
   ])

# Check for libcap POSIX.1e capability support
CHECK_LIBCAP

# Checks for header files.

# Check for C POSIX library header files
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h sys/socket.h sys/time.h unistd.h sys/stat.h fcntl.h search.h regex.h])

# Check for other required header files
AC_CHECK_HEADERS([getopt.h pcap.h sys/ioctl.h ifaddrs.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
# All of these are defined by POSIX
AC_CHECK_FUNCS([malloc gethostbyname gettimeofday inet_ntoa memset select socket strerror])
# These functions might not be present on all systems
AC_CHECK_FUNCS([getifaddrs pledge])

#
# Determine link-layer implementation to use based on the $host_os variable
#
case $host_os in
   *linux* )
      AC_MSG_NOTICE([Using packet socket link layer implementation.])
      AC_CHECK_HEADERS([netpacket/packet.h net/if.h])
      AC_LIBOBJ([link-packet-socket])
      ;;
   *freebsd* | *darwin* | *openbsd* | *netbsd* | *dragonfly* )
      AC_MSG_NOTICE([Using BPF link layer implementation.])
# We need to specify additional headers to include here, because several
# BSD variants require certain headers to be included before others will
# work.
# FreeBSD 5.2 needs sys/socket.h included for net/if, and
# needs sys/types.h for sys/sysctl.h and net/bpf.h
# OpenBSD 3.9 needs sys/param.h included for sys/sysctl.h
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
      AC_MSG_NOTICE([Using DLPI link layer implementation.])
      AC_MSG_NOTICE([NOTE: This works on Solaris 8,9 and 10 but fails on Solaris 11.])
# Solaris 9 needs sys/types.h and sys/socket.h included before net/if.h.
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

# Linux and most BSD systems have getopt_long_only, but NetBSD 7.0 doesn't.
# Use the my_getopt.c implementation for systems that don't have it.
AC_CHECK_FUNC([getopt_long_only],
              [AC_DEFINE(HAVE_GETOPT_LONG_ONLY, 1, [Define to 1 if the C library includes getopt_long_only])],
              [ AC_LIBOBJ([my_getopt])
                AC_LIBSOURCE([my_getopt.h]) ])

# Check for strlcpy.  If we don't have it, use the replacement function
# from OpenBSD.  This is needed for systems using glibc.
AC_CHECK_FUNC([strlcpy],
              [AC_DEFINE(HAVE_STRLCPY, 1, [Define to 1 if the C library includes the strlcpy function])],
              [ AC_LIBOBJ([strlcpy])
                AC_LIBSOURCE([strlcpy.h]) ])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
