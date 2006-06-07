# $Id: Makefile.am 7406 2006-05-30 12:23:21Z rsh $
# Process this file with automake to produce Makefile.in
#
AM_CPPFLAGS = -DDATADIR=\"$(pkgdatadir)\"
#
bin_PROGRAMS = arp-scan
#
dist_bin_SCRIPTS = get-oui.pl arp-fingerprint.pl
#
dist_check_SCRIPTS = check-arp-scan-run1
#
dist_man_MANS = arp-scan.1 get-oui.1
#
arp_scan_SOURCES = arp-scan.c arp-scan.h error.c wrappers.c
arp_scan_LDADD = $(LIBOBJS)
#
dist_pkgdata_DATA = oui.txt
#
TESTS = $(dist_check_SCRIPTS)
