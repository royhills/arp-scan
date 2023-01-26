# arp-scan

[![Build](https://github.com/royhills/arp-scan/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/royhills/arp-scan/actions/workflows/c-cpp.yml)
[![Coverage Status](https://coveralls.io/repos/github/royhills/arp-scan/badge.svg?branch=master)](https://coveralls.io/github/royhills/arp-scan?branch=master)
[![CodeQL](https://github.com/royhills/arp-scan/actions/workflows/codeql.yml/badge.svg)](https://github.com/royhills/arp-scan/actions/workflows/codeql.yml)

---

## Table of Contents

- [About](#about)
- [Installation](#installation)
- [Documentation](#documentation)
- [Notes for Contributors](#notes-for-contributors)
- [Coding Guidelines](#coding-guidelines)

## About

arp-scan is a command-line tool that uses the ARP protocol to discover and fingerprint IPv4 hosts on the local network. It is available for Linux, BSD (including macOS) and Solaris under the GPLv3 licence.

## Installation

arp-scan uses the GNU automake and autoconf tools, so the typical installation process is:

- ```git clone https://github.com/royhills/arp-scan.git``` to obtain the latest source code
- ```cd arp-scan```
- ```autoreconf --install``` to generate a configure file (but you can download a tarball for the latest release instead of cloning from github if you don't have `autoreconf` - see below for details)
- ```./configure``` to create a makefile for your system (see configuration options below)
- ```make``` to build the project
- Optionally ```make check``` to verify that everything works as expected
- ```make install``` to install (you'll need to be root or use sudo/doas for this part)

You will need:

- GNU `automake` and `autoconf` (if you don't have these, download the latest tarball which includes `configure`: [arp-scan-1.10.0.tar.gz](https://github.com/royhills/arp-scan/releases/download/1.10.0/arp-scan-1.10.0.tar.gz)).
- The `make` utility (works with BSD make and GNU make).
- An ANSI C compiler (tested on `gcc` and `clang`, probably works on others).
- `libpcap` version 1.5 or later.
- `libcap` to build with POSIX.1e capabilities support on Linux.

To run the Perl scripts arp-fingerprint and get-oui, you will also need `perl` and the perl modules `LWP::UserAgent` and `Text::CSV`.

You can pass options to `configure` to control the build process. Run `./configure --help` for a list of options. `arp-scan` has one package-specific configure option:

- `--with-libcap[=auto/yes/no]` Build with libcap POSIX.1e capabilities support [default=`auto`]

    By default, configure will enable capability support if the `libcap` library and headers are installed. Specifying `--with-libcap` will enable support and `--without-libpcap` will disable it.

arp-scan runs on:

 - Linux
 - FreeBSD
 - OpenBSD
 - NetBSD
 - DragonflyBSD
 - macOS
 - Solaris 10 (there are known problems with Solaris 11 but I doubt anyone cares. Please comment on [the issue](https://github.com/royhills/arp-scan/issues/31) if you do).

## Documentation

For usage information use:

```arp-scan --help```

For detailed information, see the manual pages: arp-scan(1), arp-fingerprint(1), get-oui(1) and mac-vendor(5).

See the arp-scan wiki at http://www.royhills.co.uk/wiki/ (it's a bit outdated now, but I plan to update it).

## Notes for Contributors

Most of the changes and improvements came from the community. So contributions are very welcome, and I always credit the contributors in the ChangeLog.

 - [Pull Requests](https://github.com/royhills/arp-scan/pulls): If you are able to write C code. I accept most pull requests, normally after a short discussion. Please see the coding guidelines below.
 - [Issues](https://github.com/royhills/arp-scan/issues): For bug reports, feature requests, build problems, packaging issues, ideas, strange things you can't explain (I've found interesting bugs and the occasional vulnerability from weird results) etc. Please check existing issues (both [open](https://github.com/royhills/arp-scan/issues?q=is%3Aopen+is%3Aissue) and [closed](https://github.com/royhills/arp-scan/issues?q=is%3Aissue+is%3Aclosed)) and the appropriate manual page before reporting, thanks.

## Coding Guidelines

Please read these guidelines if you're submitting a pull request:

 - Must run on all supported platforms (possible exception for Solaris because it's moribund now). I can help with porting, autoconf checks, unit tests etc.
 - Must compile without warnings with the GCC/Clang options that `arp-scan` builds with.
 - Formatting like `clang-format` with the following options (with a few exceptions):
   - `BasedOnStyle: LLVM`
   - `IndentWidth: 3`
   - `AlwaysBreakAfterDefinitionReturnType: All`
   - `IndentCaseLabels: true`

## Using github branches other than `master`

Generally only contributors will do this, but anyone is welcome to.  However most people will want to use the code from the `master` branch because it has been tested. If you don't know what all that means then you don't need to read this section.

If you use github branches from a pull request, please note that:

 - The code is experimental until it gets merged into `master` (but there's pretty good checks so if it says `All checks have passed`/`This branch has no conflicts with the base branch` then you're fairly safe).
 - I may rebase the branch to master if there are no other contributors (if it's my PR and no one else has contributed to it. That's what `royhills forced-pushed ...` means if you see it.
