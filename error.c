/*
 * arp-scan is Copyright (C) 2005-2023 Roy Hills
 *
 * This file is part of arp-scan.
 *
 * arp-scan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * arp-scan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with arp-scan.  If not, see <http://www.gnu.org/licenses/>.
 *
 * error.c -- error routines for arp-scan
 *
 * Author:	Roy Hills
 * Date:	1 December 2001
 */

#include "arp-scan.h"

int daemon_proc; /* Non-zero if process is a daemon */

/*
 * Function to handle fatal system call errors.
 */
void
err_sys(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(1, fmt, ap);
   va_end(ap);
   exit(EXIT_FAILURE);
}

/*
 * Function to handle non-fatal system call errors.
 */
void
warn_sys(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(1, fmt, ap);
   va_end(ap);
}

/*
 * Function to handle fatal errors not from system calls.
 */
void
err_msg(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(0, fmt, ap);
   va_end(ap);
   exit(EXIT_FAILURE);
}

/*
 * Function to handle non-fatal errors not from system calls.
 */
void
warn_msg(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(0, fmt, ap);
   va_end(ap);
}

/*
 * General error printing function used by all the above
 * functions.
 */
void
err_print (int errnoflag, const char *fmt, va_list ap) {
   int n = 0;
   size_t size = 0;
   int errno_save;
   char *buf;
   va_list ap_copy;
   char *cp;

   errno_save=errno;
/*
 * Determine required size for the resultant string using copy
 * arg ptr.
*/
   va_copy(ap_copy, ap);
   n = vsnprintf(NULL, 0, fmt, ap_copy);
   va_end(ap_copy);
   if (n < 0)
      return; /* vsnprintf output error */

   size = (size_t) n + 1; /* One extra byte for '\0' */

   buf = Malloc(size);

   vsnprintf(buf, size, fmt, ap);
   size=strlen(buf);
   cp = buf;
   if (errnoflag) {
      buf = make_message("%s: %s\n", cp, strerror(errno_save));
   } else {
      buf = make_message("%s\n", cp);
   }
   free(cp);

   fflush(stdout); /* In case stdout and stderr are the same */
   fputs(buf, stderr);
   fflush(stderr);
}
