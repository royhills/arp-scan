# Notes for Contributors

Most of the changes and improvements to arp-scan came from the community. So contributions are very welcome.

 - [Pull Requests](https://github.com/royhills/arp-scan/pulls): Please see the coding guidelines below.
 - [Issues](https://github.com/royhills/arp-scan/issues): For bug reports, feature requests, build problems, packaging issues, ideas, strange things you can't explain etc. Please check existing issues (both [open](https://github.com/royhills/arp-scan/issues?q=is%3Aopen+is%3Aissue) and [closed](https://github.com/royhills/arp-scan/issues?q=is%3Aissue+is%3Aclosed)) and the appropriate manual page before reporting, thanks.

## Coding Guidelines

Please read these guidelines if you're submitting a pull request:

 - Must build and run on all supported platforms (possible exception for Solaris because it's moribund). The `arp-scan` team can help with porting, autoconf checks, unit tests etc.
 - Must compile without warnings with the GCC/Clang options that `arp-scan` builds with.
 - Source formatting style is `clang-format` with the following options (with a few exceptions):
   - `BasedOnStyle: LLVM`
   - `IndentWidth: 3`
   - `AlwaysBreakAfterDefinitionReturnType: All`
   - `IndentCaseLabels: true`
