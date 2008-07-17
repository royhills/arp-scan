/*
 * The ARP Scanner (arp-scan) is Copyright (C) 2005-2008 Roy Hills,
 * NTA Monitor Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * $Id$
 *
 * Author: Roy Hills
 * Date: 8 November 2003
 *
 * This file contains wrapper functions for system and library calls that
 * are not expected to fail.  If they do fail, then it calls err_sys to
 * print a diagnostic and terminate the program.  This removed the tedious
 * "if ((function()) == NULL) err_sys("function");" logic thus making the
 * code easier to read.
 *
 * The wrapper functions have the same name as the system or library function
 * but with an initial capital letter.  E.g. Gethostbyname().  This convention
 * if from Richard Steven's UNIX Network Programming book.
 *
 */

#include "arp-scan.h"

static char rcsid[] = "$Id$";	/* RCS ID for ident(1) */

/*
 * We omit the timezone arg from this wrapper since it's obsolete and we never
 * use it.
 */
int Gettimeofday(struct timeval *tv) {
   int result;

   result = gettimeofday(tv, NULL);

   if (result != 0)
      err_sys("gettimeofday");

   return result;
}

void *Malloc(size_t size) {
   void *result;

   result = malloc(size);

   if (result == NULL)
      err_sys("malloc");

   return result;
}

void *Realloc(void *ptr, size_t size) {
   void *result;

   result=realloc(ptr, size);

   if (result == NULL)
      err_sys("realloc");

   return result;
}

unsigned long int Strtoul(const char *nptr, int base) {
   char *endptr;
   unsigned long int result;

   result=strtoul(nptr, &endptr, base);
   if (endptr == nptr)  /* No digits converted */
      err_msg("ERROR: \"%s\" is not a valid numeric value", nptr);

   return result;
}

long int Strtol(const char *nptr, int base) {
   char *endptr;
   long int result;

   result=strtol(nptr, &endptr, base);
   if (endptr == nptr)  /* No digits converted */
      err_msg("ERROR: \"%s\" is not a valid numeric value", nptr);

   return result;
}

void wrappers_use_rcsid(void) {
   fprintf(stderr, "%s\n", rcsid);	/* Use rcsid to stop compiler optimising away */
}
