# Process this file with automake to produce Makefile.in
#
pkgsysconfdir = $(sysconfdir)/$(PACKAGE)
AM_CPPFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" -DPKGSYSCONFDIR=\"$(sysconfdir)/$(PACKAGE)\"
#
bin_PROGRAMS = arp-scan
#
dist_bin_SCRIPTS = get-oui get-iab arp-fingerprint
#
dist_check_SCRIPTS = check-run1 check-packet check-decode check-host-list check-ieee-reg check-error check-options check-prng
check_PROGRAMS = mt19937ar-test
mt19937ar_test_SOURCES = mt19937ar-test.c mt19937ar.c mt19937ar.h
#
dist_man_MANS = arp-scan.1 get-oui.1 arp-fingerprint.1 mac-vendor.5
#
arp_scan_SOURCES = arp-scan.c arp-scan.h error.c wrappers.c utils.c mt19937ar.c format.c mt19937ar.h
arp_scan_LDADD = $(LIBOBJS)
#
dist_pkgsysconf_DATA = mac-vendor.txt
dist_pkgdata_DATA = ieee-oui.txt
#
TESTS = $(dist_check_SCRIPTS)
EXTRA_DIST = arp-scan.1.dist get-oui.1.dist CONTRIBUTING.md SECURITY.md testdata/pkt-simple-request.dat testdata/pkt-custom-request.dat testdata/pkt-custom-request-padding.dat testdata/pkt-custom-request-llc.dat testdata/pkt-custom-request-vlan.dat testdata/pkt-simple-response.pcap testdata/pkt-padding-response.pcap testdata/pkt-vlan-response.pcap testdata/pkt-llc-response.pcap testdata/pkt-net1921681-response.pcap testdata/pkt-trailer-response.pcap testdata/pkt-vlan-llc-response.pcap testdata/pkt-custom-request-vlan-llc.dat testdata/pkt-dup-response.pcap testdata/pkt-diff-frame-addr.pcap testdata/pkt-local-admin.pcap testdata/pkt-ieee-regcheck.pcap testdata/pkt-too-short.pcap
#
# Substitute autoconf pkgdatadir variable in arp-scan.1 manpage
CLEANFILES = arp-scan.1 get-oui.1
do_subst = $(SED) -e 's,[@]PKGDATADIR[@],$(pkgdatadir),g;s,[@]PKGSYSCONFDIR[@],$(pkgsysconfdir),g'
arp-scan.1: arp-scan.1.dist Makefile
	$(do_subst) < $(srcdir)/arp-scan.1.dist > arp-scan.1
get-oui.1: get-oui.1.dist Makefile
	$(do_subst) < $(srcdir)/get-oui.1.dist > get-oui.1
# Install arp-scan with cap_net_raw if possible, otherwise SUID root
install-exec-hook:
	@if command -v setcap > /dev/null; then \
	if setcap cap_net_raw+p $(DESTDIR)$(bindir)/arp-scan$(EXEEXT); then \
	echo "setcap cap_net_raw+p $(DESTDIR)$(bindir)/arp-scan$(EXEEXT)"; \
	chmod u-s $(DESTDIR)$(bindir)/arp-scan$(EXEEXT); \
	else \
	echo "Setcap failed on $(DESTDIR)$(bindir)/arp-scan$(EXEEXT), falling back to setuid" >&2; \
	echo "chmod u+s $(DESTDIR)$(bindir)/arp-scan$(EXEEXT)";  \
	chmod u+s $(DESTDIR)$(bindir)/arp-scan$(EXEEXT);  \
	fi \
	else \
	echo "Setcap is not installed, falling back to setuid" >&2 ; \
	echo "chmod u+s $(DESTDIR)$(bindir)/arp-scan$(EXEEXT)" ;\
	chmod u+s $(DESTDIR)$(bindir)/arp-scan$(EXEEXT) ;\
	fi
