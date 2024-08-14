dnl Check whether GCC accepts -D_FORTIFY_SOURCE
dnl
dnl This was introduced in GCC 4.1 and glibc 2.4, but was present in earlier
dnl versions on redhat systems (specifically GCC 3.4.3 and above).
dnl
dnl We define the GNUC_PREREQ macro to the same definition as __GNUC_PREREQ
dnl in <features.h>. We don't use __GNUC_PREREQ directly because <features.h>
dnl is not present on all the operating systems that we support, e.g. OpenBSD.
dnl
AC_DEFUN([GCC_FORTIFY_SOURCE],[
   if test "X$CC" != "X"; then
      AC_MSG_CHECKING([whether ${CC} accepts -D_FORTIFY_SOURCE])
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[
         #define GNUC_PREREQ(maj, min) ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
         #if !(GNUC_PREREQ (4, 1) \
            || (defined __GNUC_RH_RELEASE__ && GNUC_PREREQ (4, 0)) \
            || (defined __GNUC_RH_RELEASE__ && GNUC_PREREQ (3, 4) \
               && __GNUC_MINOR__ == 4 \
               && (__GNUC_PATCHLEVEL__ > 2 \
                  || (__GNUC_PATCHLEVEL__ == 2 && __GNUC_RH_RELEASE__ >= 8))))
         #error No FORTIFY_SOURCE support
         #endif
      ]])],[
         AC_MSG_RESULT(yes)
         CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2"
      ],[
         AC_MSG_RESULT(no)
      ])
   fi
])
