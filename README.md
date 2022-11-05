# arp-scan

[![Build](https://github.com/royhills/arp-scan/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/royhills/arp-scan/actions/workflows/c-cpp.yml)
[![Coverage Status](https://coveralls.io/repos/github/royhills/arp-scan/badge.svg?branch=master)](https://coveralls.io/github/royhills/arp-scan?branch=master)
[![CodeQL](https://github.com/royhills/arp-scan/actions/workflows/codeql.yml/badge.svg)](https://github.com/royhills/arp-scan/actions/workflows/codeql.yml)

Send ARP requests to network hosts and display responses

## Table of Contents
- [Installation](#installation)
- [Documentation](#documentation)

Installation
------------

arp-scan uses the GNU automake and autoconf tools, so the typical installation process is:

- ```git clone https://github.com/royhills/arp-scan.git``` to obtain the latest project source code
- ```cd arp-scan``` to enter the source directory
- ```autoreconf --install``` to generate a configure file
- ```./configure``` to generate a makefile for your system (see below for configuration options)
- ```make``` to build the project
- Optionally ```make check``` to verify that everything works as expected
- ```make install``` to install (you'll need to be root or use sudo/doas for this part)

You will need GNU automake and autoconf, the make utility, an ANSI C compiler (tested with gcc and clang), the development header files and libraries, and libpcap version 1.5 or later. On Linux, it is recommended to install the libcap POSIX.1e capability support development header files and libraries (typically in a package called `libcap-dev`, `libcap-devel` or similar) so arp-scan can be made capabilities-aware.

If you want to run the Perl scripts arp-fingerprint and get-oui, you will need to have the Perl interpreter installed.  In addition, for get-oui, you will need the LWP::UserAgent and Text::CSV Perl modules.

You can pass various options to "configure" to control the build and installation process. Run "./configure --help" to see a list of options. arp-scan has one package-specific configure option:

- --with-libcap[=auto/yes/no] Build with libcap POSIX.1e capabilities support [default=auto]

    By default, configure will enable capability support if the *libcap* library and development headers are installed. Specifying *--with-libcap* will enable support and *--without-libpcap* will disable it.

arp-scan is known to compile and run on the following platforms:

 - Linux
 - FreeBSD
 - OpenBSD
 - NetBSD
 - DragonflyBSD
 - MacOS X
 - Solaris 10 (there are known problems with Solaris 11)

All platforms use libpcap (http://www.tcpdump.org/) to send the ARP packets and receive the responses.

The only piece of code that is implementation-specific is the function to obtain the interface MAC address. This uses Packet Socket on Linux, BPF on BSD, and DLPI on Solaris.

Documentation
-------------

The primary source of documentation is the arp-scan wiki at http://www.royhills.co.uk/wiki/

For usage information, including details of all the options, use:

```arp-scan --help```

For more detailed documentation, see the manual pages: arp-scan(1), arp-fingerprint(1), get-oui(1) and mac-vendor(5).
