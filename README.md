# arp-scan

[![Build](https://github.com/royhills/arp-scan/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/royhills/arp-scan/actions/workflows/c-cpp.yml)
[![Coverage Status](https://coveralls.io/repos/github/royhills/arp-scan/badge.svg?branch=master)](https://coveralls.io/github/royhills/arp-scan?branch=master)

The ARP scanner

## Table of Contents
- [Installation](#installation)
- [Documentation](#documentation)

Installation
------------

arp-scan uses the standard GNU automake and autoconf tools, so the typical installation process is:

- Run ```git clone https://github.com/royhills/arp-scan.git``` to obtain the latest project source code
- Run ```cd arp-scan``` to enter the source directory
- Run ```autoreconf --install``` to generate a viable ./configure file
- Run ```./configure``` to generate a makefile for your system
- Run ```make``` to build the project
- Optionally run ```make check``` to verify that everything works as expected
- Run ```make install``` to install (you'll need to be root or use sudo/doas for this part)

You will need GNU automake and autoconf, the make utility, an ANSI C compiler (for example gcc or clang), the development header files and libraries, and libpcap version 1.5 or later.

If you want to run the Perl scripts arp-fingerprint, get-oui and get-iab, you
will need to have the Perl interpreter installed.  In addition, for get-oui
and get-iab, you will need the LWP::UserAgent Perl module.

You can pass various options to "configure" to control the build and
installation process.  See the file INSTALL for more details.

arp-scan is known to compile and run on the following platforms:

 - Linux
 - FreeBSD
 - OpenBSD
 - NetBSD
 - DragonflyBSD
 - MacOS X
 - Solaris 10 (there are known problems with Solaris 11)

All platforms use libpcap (http://www.tcpdump.org/) to send the ARP packets
and receive the responses.

The only piece of the code that is implementation-specific is the function to
obtain the interface MAC address. This uses Packet Socket on Linux, BPF on
BSD and DLPI on Solaris.

Documentation
-------------

The primary source of documentation is the arp-scan wiki at
http://www.royhills.co.uk/wiki/

For usage information, including details of all the options, use:

```arp-scan --help```

For more detailed documentation, see the manual pages: arp-scan(1),
arp-fingerprint(1), get-iab(1), get-oui(1) and mac-vendor(5).
