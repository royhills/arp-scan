**This file gives a brief overview of the major changes between each arp-scan
release.  For more details please read the ChangeLog file.**

# 2022-12-10 arp-scan 1.10.0 (git tag 1.10.0)

## New Features

* **POSIX.1e capabilities support for Linux systems with libcap.**

  - Uses `CAP_NET_RAW` capability instead of superuser (root) permissions.
  - May need `libcap-dev` or similar package to build. *Note that `libcap`
    (capabilities) and `libpcap` (packet capture) are different libraries.*
  - configure option `--with-libcap`, defaults to auto.
  - Can set capability on exe with: `setcap cap_net_raw+p /path/to/arp-scan`
  - Initially clears effective set completely and clears everything except
    CAP_NET_RAW from the permitted set. Only enables CAP_NET_RAW in effective
    set for the functions that open raw sockets. Once sockets opened, removes
    CAP_NET_RAW from both effective and permitted set so process can never
    re enable it.
  - If arp-scan is SUID root, will drop all capabilities except CAP_NET_RAW
    as above and will also drop SUID with `setuid(getuid())`. So SUID root is
    essentially as secure as `setcap cap_net_raw+p /path/to/arp-scan` and is a
    safe alternative if the filesystem does not support extended attributes.
  - If arp-scan is run as root, e.g. `sudo`, it will drop all capabilities
    except CAP_NET_RAW and proceed as previously, but will remain as UID 0
    and may encounter file permissions issues if it tries to open files with
    e.g. `--pcapsavefile` or `--ouifile` in user directories.
  - `--version` displays `Built with libcap POSIX.1e capability support` if
    enabled.
  - `make install` installs the arp-scan executable with the `CAP_NET_RAW`
    capability if `setcap` is available and works. Otherwise will fallback to
    SUID. See `install-exec-hook` in `Makefile.am` for details.

* **--format option allows flexible output format.**

  - Fields and text with \ character escapes, e.g. `${ip}\t${mac}\t${vendor}`
  - Optional left/right aligned width, e.g. `|${ip;-15}|${mac}|`
  - XML: `<host><ip>${ip}</ip><mac>${mac}</mac><vendor>${vendor}</vendor></host>`
  - JSON: `{"ipAddress":"${ip}", "macAddress":"${mac}", "vendor":"${vendor}"},`
  - See the arp-scan manpage for details of field names and more examples.

* **Mac/Vendor mapping file changes.**

  - `ieee-oui.txt` now holds data for all IEEE registries: MA-L (OUI), MA-M,
    MA-S (OUI36) and IAB.
  - `ieee-iab.txt` file and `--iabfile` option have been removed.
  - `get-oui` now updates `ieee-oui.txt` from all registries. `get-iab` has been
    removed.
  - `get-oui` requires Perl module `Text::CSV` as it now uses the IEEE .csv
    files instead of the .txt files.
  - `get-oui` can be edited to use the data from the Debian `ieee-data` package.
  - `mac-vendor.txt` is now installed to `$(sysconfdir)/$(PACKAGE)` instead of
    `$(pkgdatadir)`. E.g. `/usr/local/etc/arp-scan` if ./configured with no
    directory options, or `/etc/arp-scan` with `--sysconfdir=/etc`. This is to
    permit local changes to persist across upgrades.

## General improvements

* Put man pages and `--help` output on a diet. Updated for new options.
* Option value length is now limited only by the maximum command line
  length (normally around 100K). This allows for complex `--format` options,
  long `--padding` lengths etc.
* arp-scan now prints a brief error message instead of half a page of usage
  text for unknown options.

# 2022-10-08 arp-scan 1.9.8 (git tag 1.9.8)

* New Features:

  - Allow the use of Linux IP aliases such as `eth0:0` for the interface name.
  - Permit regular MAC addresses e.g. `00:0c:29:b9:43:1b` in `mac-vendor.txt`.
  - `--limit=n` option exits after n of hosts have responded, exit 1 for <n
  - `--resolve` option to resolve responding IP addresses to hostnames

* Fixed bugs:

  - Potential buffer overrun in `unmarshal_arp_pkt()`.
  - arp-scan aborts with `EAGAIN` on busy network or using high bandwidth
  - late ARP responses could sometimes be incorrectly flagged as duplicate

* General improvements:

  - Updated IEEE URLs in download perl scripts.
  - Updated source for Mersenne RNG and replacement strlcat/strlcpy & getopt.
  - Updated for compatability with autoconf 2.71
  - `make distcheck` works now
  - Number of responding hosts reported no longer counts duplicate packets.
  - Many typos corrected and edge cases fixed.

* Misc Changes:

  - CI framework migrated from travis-ci to github actions.
  - Several new tests for `make check`

# 2019-11-10 arp-scan 1.9.7

* Improved error messages from libpcap functions.

* Remove obsolescent and unused autoconf macros.  arp-scan 1.9.7 assumes that
  the C compiler is ANSI C (C89) compliant.

# 2019-10-13 arp-scan 1.9.6

* Use libpcap function `pcap_set_immediate_mode()` instead of ioctl calls to
  ensure packets are delivered immediately. This fixes the bug which caused
  arp-scan on linux to not report any hosts with libpcap 1.9.1. This change
  means arp-scan now requires libpcap 1.5.0 or later and will not work with
  earlier versions.

* Fix compiler warnings caused by the depreciated function `pcap_lookupdev()`
  in libpcap 1.9.0 and later.

# 2016-09-03 arp-scan 1.9.5

* Use posix hash table functions `hcreate()`, `hsearch()` and `hdestroy()`
  instead of the gas hash table code. Thanks to nihilus for the suggestion.

* Remove function replacement for `inet_aton()`, as this was only required for
  Solaris 8, which is now considered obsolete.

* Added arp-fingerprint patterns for FreeBSD 10.3, DragonflyBSD 4.6, Windows10,
  Linux 4.0, Linux 4.6, OpenBSD 5.9, NetBSD 7.0.

* Added "-l" option to arp-fingerprint to support fingerprinting all hosts on
  the local network. Thanks to Rhig for the pull request.

* Use the `source_mac` rather than `interface_mac` in the pcap filter, to permit
  reception of packets with spoofed MAC source address. Thanks to tissieres
  for the pull request.

* Use the libpcap 1.0 API functions `pcap_create()` instead of `pcap_open_live()`.
  This means that arp-scan now requires libpcap 1.0 or later and will not work
  with earlier libpcap versions.

* Updated IEEE OUI and IAB download locations to reflect IEEE website changes.

* Updated IEEE OUI and IAB MAC/Vendor files.  There are now 22487 OUI entries
  and 4575 IAB entries.

# 2013-11-24 arp-scan 1.9.2

* Added new `--plain` `(-x)` option to suppress printing of header and footer text,
  and only display one output line for each responding host. Idea from Stefan
  Tomanek's arp-scan fork on github at https://github.com/wertarbyte/arp-scan.

* Use `LWP::UserAgent` instead of `LWP::Simple` in get-oui and get-iab to enable
  the raw content to be obtained, which avoids Unicode/UTF-8 issues.

* Added arp-fingerprint patterns for WIZnet W5100 and Cisco IOS 15.0.

* Moved arp-scan development from internal SVN repository to github at
  https://github.com/royhills/arp-scan. The move to git means that the commit
  object names are now SHA1 hashes instead of increasing integer values. So
  they are longer suitable for internal file versions with rcsid variables.
  Accordingly the rcsid variables have been removed.

# 2013-07-24 arp-scan 1.9:

* Updated IEEE OUI and IAB MAC/Vendor files.  There are now 18157 OUI entries
  and 4414 IAB entries.

* Use autoconf 2.69 and automake 1.11 to add support for ARM 64-bit CPUs.

* Use libpcap functions to obtain the interface IP address and send the ARP
  packet, instead of using our own link-layer specific functions. The only
  link-layer specific function that we still need is get_hardware_address()
  to obtain the interface MAC address. This means we now require libpcap 0.9.3
  or later.

* Added support for Dragonfly BSD.

* The -u option to get-iab and get-oui scripts now works.

* get-oui and get-iab scripts now get the OUI and IAB files from the new
  locations on the IEEE website, and allow whitespace at the beginning of
  the line.

* If the MAC/Vendor file locations are not explicitly specified, look for them
  in the current directory and then in their default location.

* Raised default timeout from 100ms to 500ms.

* Added new --rtt (-D) option to display the packet round-trip time.

* Include <net/bpf.h> header file early in link-bpf.c to avoid BPF symbol
  problems on some BSD based operating systems.

* Added arp-fingerprint patterns for GNU/Hurd, Amazon Kindle (Linux 2.6),
  BeOS, Windows 8, Recent Linux, FreeBSD, NetBSD and OpenBSD versions, and
  RiscOS.

* Added data file "pkt-custom-request-vlan-llc.dat" to the tarball to allow
  the ARP request packet generation self test to complete successfully.

* Various minor bug fixes and improvements.

# 2011-03-01 arp-scan 1.8:

* Updated IEEE OUI and IAB MAC/Vendor files.  There are now 14707 OUI entries
  and 3542 IAB entries.

* Added support for trailer ARP replies, which were used in early versions
  of BSD Unix on VAX.

* Added support for ARP packets with both 802.1Q VLAN tag and LLC/SNAP framing.

* The full help output is only displayed if specifically requested with
  arp-scan --help.  Usage errors now result in smaller help output.

* Added support for Apple Mac OS X with Xcode 2.5 and later. This allows
  arp-scan to build on Tiger, Leopard and Snow Leopard.

* Changed license from GPLv2 to GPLv3.

* Added warning about possible DoS when setting ar$spa to the destination IP
  address to the help output and man page.

* Added arp-fingerprint patterns for 2.11BSD, NetBSD 4.0, FreeBSD 7.0,
  Vista SP1, Windows 7 and Blackberry OS.

* Enabled compiler security options -fstack-protect, -D_FORTIFY_SOURCE=2 and
  -Wformat-security if they are supported by the compiler. Also enabled extra
  warnings -Wwrite-strings and -Wextra.

* Added new "make check" tests to check packet generation, and packet decoding
  and display.

* Modified get-oui and get-iab perl scripts so they will work on systems where
  the perl interpreter is not in /usr/bin, e.g. NetBSD.

* Various minor bug fixes and improvements.

# 2008-07-24 arp-scan 1.7:

* new --pcapsavefile (-W) option to save the ARP response packets to a pcap
  savefile for later analysis with tcpdump, wireshark or another program that
  supports the pcap file format.

* new --vlan (-Q) option to create outgoing ARP packets with an 802.1Q VLAN tag
  ARP responses with a VLAN tag are interpreted and displayed.

* New --llc (-L) option to create outgoing ARP packets with RFC 1042 LLC/SNAP
  framing. Received ARP packets are decoded and displayed with either
  LLC/SNAP or the default Ethernet-II framing irrespective of this option.

* Avoid double unmarshalling of packet data: once in callback, then again in
  display_packet().

* New arp-fingerprint patterns for ARP fingerprinting: Cisco 79xx IP Phone
  SIP 5.x, 6.x and 7.x; Cisco 79xx IP Phone SIP 8.x.

* Updated IEEE OUI and IAB MAC/Vendor files.  There are now 11,697 OUI entries
  and 2,386 IAB entries.

# 2007-04-12 arp-scan 1.6:

* arp-scan wiki at http://www.nta-monitor.com/wiki/
  This contains detailed documentation on arp-scan, and is intended to be
  the primary documentation resource.

* Added support for Sun Solaris.  Tested on Solaris 9 (SPARC).  arp-scan may
  also work on other systems that use DLPI, but only Solaris has been tested.

* New arp-fingerprint patterns for ARP fingerprinting: IOS 11.2, 11.3 and 12.4;
  ScreenOS 5.1, 5.2, 5.3 and 5.4; Cisco VPN Concentrator 4.7; AIX 4.3 and 5.3;
  Nortel Contivity 6.00 and 6.05; Cisco PIX 5.1, 5.2, 5.3, 6.0, 6.1, 6.2, 6.3
  and 7.0.

* Updated IEEE OUI and IAB MAC/Vendor files.  There are now 10,214 OUI entries
  and 1,858 IAB entries.

* Added HSRP MAC address to mac-vendor.txt.

# 2006-07-22 arp-scan 1.5:

* Reduced memory usage from 44 bytes per target to 28 bytes.  This reduces
  the memory usage for a Class-B network from 2.75MB to 1.75MB, and a Class-A
  network from 704MB to 448MB.

* Reduced the startup time for large target ranges.  This reduces the startup
  time for a Class-A network from 80 seconds to 15 seconds on a Compaq laptop
  with 1.4GHz CPU.

* Added support for FreeBSD, OpenBSD, NetBSD and MacOS X (Darwin). arp-scan
  will probably also work on other operating systems that implement BPF, but
  only those listed have been tested.

* Improved operation of the --srcaddr option.  Now this will change the
  source hardware address in the Ethernet header without changing the
  interface address.

* Additional fingerprints for arp-fingerprint.

* Improved manual pages.

* Updated IEEE OUI and IAB files.  There are now 9,426 OUI entries and 1,568
  IAB entries.

# 2006-06-26 arp-scan 1.4:

* Added IEEE IAB listings and associated get-iab update script and --iabfile
  option.
* Added manual MAC/Vendor mapping file: mac-vendor.txt and associated
  --macfile option.
* New --localnet option to scan all IP addresses on the specified interface
  network and mask.

# 2006-06-23 arp-scan 1.3:

* Initial public release.  Source distribution only, which will compile and
  run on Linux.
