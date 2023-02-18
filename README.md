# arp-scan

[![Build](https://github.com/royhills/arp-scan/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/royhills/arp-scan/actions/workflows/c-cpp.yml)
[![Coverage Status](https://coveralls.io/repos/github/royhills/arp-scan/badge.svg?branch=master)](https://coveralls.io/github/royhills/arp-scan?branch=master)
[![CodeQL](https://github.com/royhills/arp-scan/actions/workflows/codeql.yml/badge.svg)](https://github.com/royhills/arp-scan/actions/workflows/codeql.yml)

---

# About

*arp-scan* is a network scanning tool that uses the ARP protocol to discover and fingerprint IPv4 hosts on the local network. It is available for Linux, BSD, macOS and Solaris under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html) licence.

This is `README.md` for *arp-scan* version `1.10.1-git`.

# Installation

## Building and Installing from Source

*arp-scan* uses the GNU *automake* and *autoconf* tools. The installation process from the latest *github* source is:

- `git clone https://github.com/royhills/arp-scan.git` to obtain the latest source code.
- `cd arp-scan` to enter the source code directory.
- `autoreconf --install` to generate a configure file (but you can download a tarball for the latest release instead of cloning from github if you don't have `autoreconf` - see below for details).
- `./configure` to create a makefile for your system (see configuration options below).
- `make` to build the project.
- Optionally `make check` to verify that everything works as expected.
- `make install` to install (you'll need to be root or use sudo/doas for this part).

You will need these development tools and libraries:

- GNU *automake* and *autoconf* (if you don't have these, you can download the latest tarball which includes `configure` instead: [arp-scan-1.10.0.tar.gz](https://github.com/royhills/arp-scan/releases/download/1.10.0/arp-scan-1.10.0.tar.gz)). Note that this might not be as up to date as the latest *github* development version.
- The *make* utility (works with BSD make and GNU make).
- A C compiler (tested on *gcc* and *clang*, probably works on others).
- Libraries and include files for *libpcap* version 1.5 or later. All modern distros have a binary package, some split the package into seperate `libpcap` runtime and `libpcap-dev` or `libpcap-devel` development packages, in which case you need to install both to build and run.
- *libcap* to build with [POSIX.1e capabilities](https://sites.google.com/site/fullycapable/) support on Linux. Most Linux distros come with runtime support by default and have a development package available. Linux has capabilities support since kernel version `2.6.24`.

To run the Perl scripts `arp-fingerprint` and `get-oui`, you will also need the *perl* interpreter and the perl modules `LWP::UserAgent` and `Text::CSV`.

You can pass options to `configure` to control the build process. Run `./configure --help` for a list of options. *arp-scan* has one package-specific configure option:

- `--with-libcap[=auto/yes/no]` Build with libcap POSIX.1e capabilities support [default=`auto`]

    With `auto`, configure will enable capability support if the `libcap` library and headers are installed. Specifying `--with-libcap` will enable support and `--without-libpcap` will disable it.

*arp-scan* is known to build and run on:

 - **Linux** (should work on any distribution and all architectures).
 - **FreeBSD**
 - **OpenBSD**
 - **NetBSD**
 - **DragonflyBSD**
 - **macOS**
 - **Solaris 10** (there are known problems with Solaris 11. If anyone cares please comment on [issue #31](https://github.com/royhills/arp-scan/issues/31)).

It should be possible to build *arp-scan* on any OS that *libpcap* supports. If your OS supports *libpcap* but configure gives the error `configure: error: Host operating system your-os-name is not supported` please open an [issue](https://github.com/royhills/arp-scan/issues) to request porting to your OS.

## Installing from a Binary Package

Many distributions provide binary packages for *arp-scan* These won't be as up to date as the latest source on github and may not be as up to date as the latest release, but they are more convenient and will be kept up to date by the package manager. So using a binary package is often a good choice if you don't need the latest features.

If you have installed a binary package and wonder if there are useful new features on github, use `arp-scan --version` to check the version you have then see the [NEWS](NEWS.md) and [ChangeLog](ChangeLog) files on github for details of what's changed.

The details on how to install an *arp-scan* binary package depend on your distribution.

## Installing from a BSD Port

If you are using a BSD operating system you may have the option of installing from a source ports collection as well as from a binary package.

Ports automate the building and installation of source code and manage updates like a binary package. They also give the flexibility of installing from source. A source port won't be as up to date as the latest github though, but it might sometimes be more up to date than the corresponding binary package.

The details on how to install an *arp-scan* source port depend on your distribution.

# Documentation

For usage information use:

`arp-scan --help`

For detailed information, see the manual pages: `arp-scan(1)`, `arp-fingerprint(1)`, `get-oui(1)` and `mac-vendor(5)`.

See the *arp-scan* wiki at [https://github.com/royhills/arp-scan/wiki](https://github.com/royhills/arp-scan/wiki)

See [`CONTRIBUTING.md`](CONTRIBUTING.md) if you are interested in contributing to *arp-scan*. If you think you have found a security vulnerability, please see [`SECURITY.md`](SECURITY.md).

# Notes for Package Maintainers

 - Please raise a github issue or create a pull request if you have any local patches that could be applicable upstream.
 - If you are building on Linux, please build with `libcap` POSIX.1e capabilities support if you can. You may need to install the `libcap` development headers as well as the `libpcap` development headers before running `configure`.
 - Note that `Makefile.am` contains an `install-exec-hook` that will install *arp-scan* with `CAP_NET_RAW` capabilities if it can, and failing that it will install it suid root.
