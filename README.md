# arp-scan

[![Build](https://github.com/royhills/arp-scan/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/royhills/arp-scan/actions/workflows/c-cpp.yml)
[![Coverage Status](https://coveralls.io/repos/github/royhills/arp-scan/badge.svg?branch=master)](https://coveralls.io/github/royhills/arp-scan?branch=master)
[![CodeQL](https://github.com/royhills/arp-scan/actions/workflows/codeql.yml/badge.svg)](https://github.com/royhills/arp-scan/actions/workflows/codeql.yml)

---

# About

`arp-scan` is a network scanning tool that uses the ARP protocol to discover and fingerprint IPv4 hosts on the local network. It is available for Linux, BSD (including macOS) and Solaris under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html) licence.

# Installation

## Building and Installing from Source

arp-scan uses the GNU automake and autoconf tools, so the typical installation process is:

- `git clone https://github.com/royhills/arp-scan.git` to obtain the latest source code.
- `cd arp-scan` to enter the source code directory.
- `autoreconf --install` to generate a configure file (but you can download a tarball for the latest release instead of cloning from github if you don't have `autoreconf` - see below for details).
- `./configure` to create a makefile for your system (see configuration options below).
- `make` to build the project.
- Optionally `make check` to verify that everything works as expected.
- `make install` to install (you'll need to be root or use sudo/doas for this part).

You will need:

- GNU `automake` and `autoconf` (if you don't have these, you can download the latest tarball which includes `configure` instead: [arp-scan-1.10.0.tar.gz](https://github.com/royhills/arp-scan/releases/download/1.10.0/arp-scan-1.10.0.tar.gz)). That won't be as up to date as github, but it will be better tested.
- The `make` utility (works with BSD make and GNU make).
- An ANSI C compiler (tested on `gcc` and `clang`, probably works on others).
- `libpcap` version 1.5 or later (any modern distro should have this as a binary package).
- `libcap` to build with [POSIX.1e capabilities](https://sites.google.com/site/fullycapable/) support on Linux. Most Linux distros should come with runtime support by default and have a binary development package available. Capabilities support has been in the Linux kernel since `2.6.24` released in January 2008, and all distros I'm aware of enable support in their kernel.

To run the Perl scripts `arp-fingerprint` and `get-oui`, you will also need `perl` and the perl modules `LWP::UserAgent` and `Text::CSV`.

You can pass options to `configure` to control the build process. Run `./configure --help` for a list of options. `arp-scan` has one package-specific configure option:

- `--with-libcap[=auto/yes/no]` Build with libcap POSIX.1e capabilities support [default=`auto`]

    With `auto`, configure will enable capability support if the `libcap` library and headers are installed. Specifying `--with-libcap` will enable support and `--without-libpcap` will disable it.

arp-scan is known to build and run on:

 - Linux
 - FreeBSD
 - OpenBSD
 - NetBSD
 - DragonflyBSD
 - macOS
 - Solaris 10 (there are known problems with Solaris 11 but I doubt anyone cares. Please comment on [this issue](https://github.com/royhills/arp-scan/issues/31) if you do).

## Installing from a Binary Package

Many distributions provide binary packages for `arp-scan`. These won't be as up to date as the latest source on github and may not be as up to date as the latest release, but they are more convenient and will be kept up to date by the package manager. So using a binary package is often a good choice if you don't need the latest features.

If you have installed a binary package and wonder if there are useful new features on github, use `arp-scan --version` to check the version you have then see the [NEWS](NEWS.md) and [ChangeLog](ChangeLog) files on github for details of what's changed.

The details on how to install an `arp-scan` binary package depend on your distribution.

## Installing from a BSD Port

If you are using a BSD operating system you may have the option of installing from a source ports collection as well as from a binary package.

Ports automate the building and installation of source code and manage updates like a binary package. They also give the flexibility of installing from source. A source port won't be as up to date as the latest github though, but it might sometimes be more up to date than the corresponding binary package.

The details on how to install an `arp-scan` source port depend on your distribution.

# Documentation

For usage information use:

`arp-scan --help`

For detailed information, see the manual pages: `arp-scan(1)`, `arp-fingerprint(1)`, `get-oui(1)` and `mac-vendor(5)`.

See the arp-scan wiki at http://www.royhills.co.uk/wiki/ (it's a bit outdated now, but I plan to update it soon).

# Notes for Contributors

Most of the changes and improvements to arp-scan came from the community. So contributions are very welcome, and I always credit the contributors in the ChangeLog.

 - [Pull Requests](https://github.com/royhills/arp-scan/pulls): I accept most pull requests but obviously no guarantees. Please see the coding guidelines below.
 - [Issues](https://github.com/royhills/arp-scan/issues): For bug reports, feature requests, build problems, packaging issues, ideas, strange things you can't explain (I've found interesting bugs and the occasional vulnerability from weird results) etc. Please check existing issues (both [open](https://github.com/royhills/arp-scan/issues?q=is%3Aopen+is%3Aissue) and [closed](https://github.com/royhills/arp-scan/issues?q=is%3Aissue+is%3Aclosed)) and the appropriate manual page before reporting, thanks.

## Coding Guidelines

Please read these guidelines if you're submitting a pull request:

 - It must build and run on all supported platforms (possible exception for Solaris because it's moribund now). I can help with porting, autoconf checks, unit tests etc.
 - It must compile without warnings with the GCC/Clang options that `arp-scan` builds with.
 - Source formatting style is `clang-format` with the following options (with a few exceptions):
   - `BasedOnStyle: LLVM`
   - `IndentWidth: 3`
   - `AlwaysBreakAfterDefinitionReturnType: All`
   - `IndentCaseLabels: true`

## Using github branches other than master

Code on the `master` branch has been tested, so that is what the vast majority of people should use. If you use github branches from a pull request, please note that:

 - The code is experimental until it gets merged into `master` (but there's still pretty good checks so if it says `All checks have passed`/`This branch has no conflicts with the base branch` then you're fairly safe providing you've read the pull request comments).
 - I may rebase the branch to master if there are no other contributors (if it's my PR and no one else has contributed to it). That's what `royhills forced-pushed ...` means if you see it.

# Notes for Package Maintainers

 - Please raise a github issue or create a pull request if you have any local patches that could be applicable upstream.
 - If you are building on Linux, please build with `libcap` POSIX.1e capabilities support if you can. You may need to install the `libcap` development headers as well as the `libpcap` development headers before running `configure`.
 - Note that `Makefile.am` contains an `install-exec-hook` that will install `arp-scan` with `CAP_NET_RAW` capabilities if it can, and failing that it will install it suid root.
