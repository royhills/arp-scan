dnl $Id$
dnl Process this file with autoconf to produce a configure script.

AC_INIT([arp-scan], [1.5.2], [arp-scan@nta-monitor.com])
AC_PREREQ(2.59)
AC_REVISION($Revision$)
AC_CONFIG_SRCDIR([arp-scan.c])
AM_INIT_AUTOMAKE(1.9)

AM_CONFIG_HEADER([config.h])

AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_CC
 if test -n "$GCC"; then
      CFLAGS="$CFLAGS -Wall "
dnl Uncomment the line below for testing with stricter warnings.
dnl      CFLAGS="$CFLAGS -pedantic -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wnested-externs "
 fi
AC_PROG_INSTALL
AC_PROG_LN_S

dnl Checks for libraries.
dnl Solaris 8 needs nsl and socket.  Linux and {Free,Open}BSD do not.
dnl Just about everything will need pcap.
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([pcap_open_live], [pcap], ,
   AC_MSG_ERROR([Cannot find libpcap library containing pcap_open_live]))

dnl Check that the pcap library contains pcap_datalink_val_to_name.
dnl This was introduced in version 0.8, and our application requires it.
dnl
dnl We perform this check as a seperate step, rather than just checking for
dnl pcap_datalink_val_to_name in the earlier AC_SEARCH_LIBS call, because it
dnl allows us to provide different error messages for missing pcap and non
dnl functional pcap and so avoids confusing generic error messages.
dnl
AC_MSG_CHECKING([for a compatible pcap library])
AC_LINK_IFELSE([AC_LANG_CALL([], [pcap_datalink_val_to_name])],
   [AC_MSG_RESULT([yes])],
   [
   AC_MSG_RESULT([no])
   AC_MSG_NOTICE([Cannot find pcap_datalink_val_to_name in pcap library])
   AC_MSG_ERROR([Check that the pcap library is at least version 0.8])
   ])

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h sys/socket.h sys/time.h syslog.h unistd.h getopt.h pcap.h sys/ioctl.h])

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
   *freebsd* | *darwin* | *openbsd* | *netbsd* )
      AC_MSG_NOTICE([Using BPF link layer implementation.]);
dnl We need to specify additional headers to include here, because several
dnl BSD variants require certain headers to be included before others will
dnl work.
dnl FreeBSD 5.2 needs sys/socket.h included for net/if, and
dnl needs sys/types.h for sys/sysctl.h and net/bpf.h
dnl OpenBSD 3.9 needs sys/param.h included for sys/sysctl.h
      AC_CHECK_HEADERS([fcntl.h net/if.h net/bpf.h sys/param.h sys/sysctl.h net/route.h net/if_dl.h],,,
      [
      #include <sys/types.h>
      #ifdef HAVE_SYS_SOCKET_H
      #include <sys/socket.h>
      #endif
      #ifdef HAVE_SYS_PARAM_H
      #include <sys/param.h>
      #endif
      ])
      AC_DEFINE(ARP_PCAP_BPF, 1, [Define to 1 if pcap uses BPF])
      AC_LIBOBJ([link-bpf])
      ;;
   *solaris* )
      AC_MSG_NOTICE([Using DLPI link layer implementation.]);
dnl Solaris 9 needs sys/types.h and sys/socket.h included before net/if.h.
      AC_CHECK_HEADERS([sys/dlpi.h sys/dlpihdr.h sys/stat.h fcntl.h stropts.h sys/ioctl.h sys/sockio.h net/if.h],,,
      [
      #include <sys/types.h>
      #ifdef HAVE_SYS_SOCKET_H
      #include <sys/socket.h>
      #endif
      ])
      AC_DEFINE(ARP_PCAP_DLPI, 1, [Define to 1 if pcap uses DLPI])
      AC_LIBOBJ([link-dlpi])
      ;;
dnl   *cygwin* )
   * )
      AC_MSG_ERROR([Host operating system $host_os is not supported])
      ;;
esac

dnl GNU systems e.g. Linux have getopt_long_only, but many other systems
dnl e.g. FreeBSD 4.3 and Solaris 8 do not.  For systems that don't have it,
dnl use the GNU getopt sources (obtained from glibc).
AC_CHECK_FUNC([getopt_long_only], ,
  [ AC_LIBOBJ(getopt)
    AC_LIBOBJ(getopt1)
    AC_LIBSOURCE(getopt.h) ])

dnl Do we have inet_aton?  Most systems do, but some e.g. Solaris don't
dnl If we don't have it, then use Russ Allbery's implementation as a
dnl replacement function.
AC_CHECK_FUNC(inet_aton, , [ AC_LIBOBJ(inet_aton) ])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
