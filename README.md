# arp-scan

[![Build](https://github.com/royhills/arp-scan/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/royhills/arp-scan/actions/workflows/c-cpp.yml)
[![Coverage Status](https://coveralls.io/repos/github/royhills/arp-scan/badge.svg?branch=master)](https://coveralls.io/github/royhills/arp-scan?branch=master)
[![CodeQL](https://github.com/royhills/arp-scan/actions/workflows/codeql.yml/badge.svg)](https://github.com/royhills/arp-scan/actions/workflows/codeql.yml)

---

## Table of Contents
- [About](#about)
- [Installation](#installation)
- [Documentation](#documentation)

About
-----

arp-scan is a command-line tool that uses the ARP protocol to discover and fingerprint IPv4 hosts on the local network. It is available for Linux, BSD (including macOS) and Solaris under the GPLv3 licence.

Installation
------------

arp-scan uses the GNU automake and autoconf tools, so the typical installation process is:

- ```git clone https://github.com/royhills/arp-scan.git``` to obtain the latest source code
- ```cd arp-scan```
- ```autoreconf --install``` to generate a configure file
- ```./configure``` to create a makefile for your system (see configuration options below)
- ```make``` to build the project
- Optionally ```make check``` to verify that everything works as expected
- ```make install``` to install (you'll need to be root or use sudo/doas for this part)

You will need:

- GNU `automake` and `autoconf`.
- The `make` utility.
- An ANSI C compiler (works with `gcc` and `clang`).
- `libpcap` version 1.5 or later.
- `libcap` to build with POSIX.1e capabilities support on Linux.

To run the Perl scripts arp-fingerprint and get-oui, you will also need `perl` and the perl modules `LWP::UserAgent` and `Text::CSV`.

You can pass options to "configure" to control the build process. Run "./configure --help" for a list of options. arp-scan has one package-specific configure option:

- --with-libcap[=auto/yes/no] Build with libcap POSIX.1e capabilities support [default=auto]

    By default, configure will enable capability support if the *libcap* library and headers are installed. Specifying *--with-libcap* will enable support and *--without-libpcap* will disable it.

arp-scan runs on:

 - Linux
 - FreeBSD
 - OpenBSD
 - NetBSD
 - DragonflyBSD
 - macOS X
 - Solaris 10 (there are known problems with Solaris 11)

Documentation
-------------

For usage information use:

```arp-scan --help```

For detailed information, see the manual pages: arp-scan(1), arp-fingerprint(1), get-oui(1) and mac-vendor(5).

See the arp-scan wiki at http://www.royhills.co.uk/wiki/
