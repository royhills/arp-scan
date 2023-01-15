/*
 * arp-scan is Copyright (C) 2005-2022 Roy Hills
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
 * You are encouraged to send comments, improvements or suggestions
 * at the github repository https://github.com/royhills/arp-scan
 *
 * Author: Roy Hills
 * Date: 5 April 2004
 *
 * This file contains various utility functions used by arp-scan.
 */

#include "arp-scan.h"

static uid_t uid;
#ifndef HAVE_LIBCAP
static uid_t euid;
#endif

/*
 *	timeval_diff -- Calculates the difference between two timevals
 *	and returns this difference in a third timeval.
 *
 *	Inputs:
 *
 *	a       = First timeval
 *	b       = Second timeval
 *	diff    = Difference between timevals (a - b).
 *
 *	Returns:
 *
 *	None.
 */
void
timeval_diff(const struct timeval *a, const struct timeval *b,
             struct timeval *diff) {
   struct timeval temp;

   temp.tv_sec = b->tv_sec;
   temp.tv_usec = b->tv_usec;

   /* Perform the carry for the later subtraction by updating b. */
   if (a->tv_usec < temp.tv_usec) {
      int nsec = (temp.tv_usec - a->tv_usec) / 1000000 + 1;
      temp.tv_usec -= 1000000 * nsec;
      temp.tv_sec += nsec;
   }
   if (a->tv_usec - temp.tv_usec > 1000000) {
      int nsec = (a->tv_usec - temp.tv_usec) / 1000000;
      temp.tv_usec += 1000000 * nsec;
      temp.tv_sec -= nsec;
   }

   /* Compute the time difference
      tv_usec is certainly positive. */
   diff->tv_sec = a->tv_sec - temp.tv_sec;
   diff->tv_usec = a->tv_usec - temp.tv_usec;
}

/*
 *	hstr_i -- Convert two-digit hex string to unsigned integer
 *
 *	Inputs:
 *
 *	cptr	Two-digit hex string
 *
 *	Returns:
 *
 *	Number corresponding to input hex value.
 *
 *	An input of "0A" or "0a" would return 10.
 *	Note that this function does no sanity checking, it's up to the
 *	caller to ensure that *cptr points to at least two hex digits.
 *
 *	This function is a modified version of hstr_i at www.snippets.org.
 */
unsigned int
hstr_i(const char *cptr) {
   unsigned int i;
   unsigned int j = 0;
   int k;

   for (k=0; k<2; k++) {
      i = *cptr++ - '0';
      if (9 < i)
         i -= 7;
      j <<= 4;
      j |= (i & 0x0f);
   }
   return j;
}

/*
 *	hex2data -- Convert hex string to binary data
 *
 *	Inputs:
 *
 *	string		The string to convert
 *	data_len	(output) The length of the resultant binary data
 *
 *	Returns:
 *
 *	Pointer to the binary data.
 *
 *	The returned pointer points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.  If the length of
 *	the input string is not even, the function will return NULL and
 *	set data_len to 0.
 */
unsigned char *
hex2data(const char *string, size_t *data_len) {
   unsigned char *data;
   unsigned char *cp;
   unsigned i;
   size_t len;

   if (strlen(string) % 2) { /* Length is odd */
      *data_len = 0;
      return NULL;
   }

   len = strlen(string) / 2;
   data = Malloc(len);
   cp = data;
   for (i=0; i<len; i++)
      *cp++ = hstr_i(&string[i*2]);
   *data_len = len;
   return data;
}

/*
 *	make_message -- allocate a sufficiently large string and print into it.
 *
 *	Inputs:
 *
 *	Format and variable number of arguments.
 *
 *	Outputs:
 *
 *	Pointer to the string,
 *
 *	This function was adapted from the example in the printf() man page
 *	from The Linux man-pages project. Modified slightly to use wrapper
 *	function for malloc.
 *
 *	The pointer returned points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.
 */
char *
make_message(const char *fmt, ...) {
   int n = 0;
   size_t size = 0;
   char *p = NULL;
   va_list ap;
   /*
    * Determine required size for the resultant string.
    */
   va_start(ap, fmt);
   n = vsnprintf(p, size, fmt, ap);
   va_end(ap);

   if (n < 0)
      return NULL; /* vsnprintf output error */

   size = (size_t)n + 1; /* One extra byte for '\0' */
   p = Malloc(size);
   /*
    * Print into the allocated space.
    */
   va_start(ap, fmt);
   n = vsnprintf(p, size, fmt, ap);
   va_end(ap);

   if (n < 0) {
      free(p);
      return NULL;
   }

   return p;
}

/*
 *	hexstring -- Convert data to printable hex string form
 *
 *	Inputs:
 *
 *	string	Pointer to input data.
 *	size	Size of input data.
 *
 *	Returns:
 *
 *	Pointer to the printable hex string.
 *
 *	Each byte in the input data will be represented by two hex digits
 *	in the output string.  Therefore the output string will be twice
 *	as long as the input data plus one extra byte for the trailing NULL.
 *
 *	The pointer returned points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.
 */
char *
hexstring(const unsigned char *data, size_t size) {
   char *result;
   char *r;
   const unsigned char *cp;
   unsigned i;
   /*
    * If the input data is NULL, return an empty string.
    */
   if (data == NULL)
      return dupstr("");
   /*
    * Create and return hex string.
    */
   result = Malloc(2*size + 1);
   cp = data;
   r = result;
   for (i=0; i<size; i++) {
      snprintf(r, 3, "%.2x", *cp++);
      r += 2;
   }
   *r = '\0';

   return result;
}

/*
 * get_ether_addr -- Get Ethernet hardware address from text string
 *
 * Inputs:
 *
 * address_string	The text string containing the address
 * ether_addr		(output) The Ethernet hardware address
 *
 * Returns:
 *
 * Zero on success or -1 on failure.
 *
 * The address_string should contain an Ethernet hardware address in one
 * of the following formats:
 *
 * 01-23-45-67-89-ab
 * 01:23:45:67:89:ab
 *
 * The hex characters [a-f] may be specified in either upper or lower case.
 */
int
get_ether_addr(const char *address_string, unsigned char *ether_addr) {
   unsigned mac_b0, mac_b1, mac_b2, mac_b3, mac_b4, mac_b5;
   int result;

   result = sscanf(address_string,
                   "%2x%*[:-]%2x%*[:-]%2x%*[:-]%2x%*[:-]%2x%*[:-]%2x",
                   &mac_b0, &mac_b1, &mac_b2, &mac_b3, &mac_b4, &mac_b5);
   if (result != 6)
      return -1;

   ether_addr[0] = mac_b0;
   ether_addr[1] = mac_b1;
   ether_addr[2] = mac_b2;
   ether_addr[3] = mac_b3;
   ether_addr[4] = mac_b4;
   ether_addr[5] = mac_b5;

   return 0;
}

/*
 *	str_to_bandwidth -- Convert a bandwidth string to unsigned integer
 *
 *	Inputs:
 *
 *	bandwidth_string	The bandwidth string to convert
 *
 *	Returns:
 *
 *	The bandwidth in bits per second as an unsigned integer
 */
unsigned
str_to_bandwidth(const char *bandwidth_string) {
   char *bandwidth_str;
   size_t bandwidth_len;
   unsigned value;
   int multiplier = 1;
   int end_char;

   bandwidth_str = dupstr(bandwidth_string); /* Writable copy */
   bandwidth_len = strlen(bandwidth_str);
   end_char = bandwidth_str[bandwidth_len-1];
   if (!isdigit(end_char)) { /* End character is not a digit */
      bandwidth_str[bandwidth_len-1] = '\0'; /* Remove last character */
      switch (end_char) {
         case 'M':
         case 'm':
            multiplier = 1000000;
            break;
         case 'K':
         case 'k':
            multiplier = 1000;
            break;
         default:
            err_msg("ERROR: Unknown bandwidth multiplier character: \"%c\"",
                    end_char);
            break;
      }
   }
   value = Strtoul(bandwidth_str, 10);
   free(bandwidth_str);
   return multiplier * value;
}

/*
 *	str_to_interval -- Convert an interval string to unsigned integer
 *
 *	Inputs:
 *
 *	interval_string		The interval string to convert
 *
 *	Returns:
 *
 *	The interval in microseconds as an unsigned integer
 */
unsigned
str_to_interval(const char *interval_string) {
   char *interval_str;
   size_t interval_len;
   unsigned value;
   int multiplier = 1000;
   int end_char;

   interval_str = dupstr(interval_string); /* Writable copy */
   interval_len = strlen(interval_str);
   end_char = interval_str[interval_len-1];
   if (!isdigit(end_char)) {               /* End character is not a digit */
      interval_str[interval_len-1] = '\0'; /* Remove last character */
      switch (end_char) {
         case 'U':
         case 'u':
            multiplier = 1;
            break;
         case 'S':
         case 's':
            multiplier = 1000000;
            break;
         default:
            err_msg("ERROR: Unknown interval multiplier character: \"%c\"",
                    end_char);
            break;
      }
   }
   value = Strtoul(interval_str, 10);
   free(interval_str);
   return multiplier * value;
}

/*
 *	dupstr -- duplicate a string
 *
 *	Inputs:
 *
 *	str	The string to duplicate
 *
 *	Returns:
 *
 *	A pointer to the duplicate string.
 *
 *	This is a replacement for the common but non-standard "strdup"
 *	function.
 *
 *	The returned pointer points to Malloc'ed memory, which must be
 *	free'ed by the caller.
 */
char *
dupstr(const char *str) {
   char *cp;
   size_t len;

   len = strlen(str) + 1; /* Allow space for terminating NULL */
   cp = Malloc(len);
   strlcpy(cp, str, len);
   return cp;
}

/*
 *	limit_capabilities -- reduce process capabilities to minimum necessary
 *
 *	Inputs:
 *
 *	none
 *
 *	Returns:
 *
 *	none
 *
 *	This function reduces the capabilities of the current process to
 *	the minimum necessary to run this program.
 *
 *	If we have POSIX.1e capability support (e.g. Linux with libcap) then
 *	remove all capabilities from the effective set and also remove all
 *	capabilities except those required by the program from the permitted
 *	set.  It will also permanantly drop SUID because SUID is not needed
 *	if capability support is present.
 *
 *	If we do not have capability support, we drop SUID by saving the
 *	effective user ID and then setting the effective user id to the real
 *	user id.
 *
 *	This function was adapted from ping_common.c in the Debian iputils-ping
 *	package.
 */
void
limit_capabilities(void) {
#ifdef HAVE_LIBCAP
   cap_t cap_cur_p;
   cap_t cap_p;
   cap_flag_value_t cap_ok;
   cap_value_t cap_list[] = {CAP_NET_RAW};
   /*
    * Create a new capability state in "cap_p" containing only those
    * capabilities that are required by the application and are present in the
    * permitted capability set.
    */
   if (!(cap_cur_p = cap_get_proc()))
      err_sys("cap_get_proc()");
   if (!(cap_p = cap_init()))
      err_sys("cap_init()");

   cap_ok = CAP_CLEAR;
   cap_get_flag(cap_cur_p, CAP_NET_RAW, CAP_PERMITTED, &cap_ok);
   if (cap_ok != CAP_CLEAR)
      cap_set_flag(cap_p, CAP_PERMITTED, sizeof(cap_list)/sizeof(cap_list[0]),
                   cap_list, CAP_SET);
   /*
    * Set the process capabilities to the new capability state.
    */
   if (cap_set_proc(cap_p) < 0)
      err_sys("cap_set_proc()");
   /*
    * Permanently drop SUID but retain capability state.
    * We don't need root UID if we have the required capabilities.
    */
   if (prctl(PR_SET_KEEPCAPS, 1) < 0)
      err_sys("prctl()");
   if (setuid(getuid()) < 0)
      err_sys("setuid()");
   if (prctl(PR_SET_KEEPCAPS, 0) < 0)
      err_sys("prctl()");
   /*
    * Free temporary capability state storage.
    */
   cap_free(cap_p);
   cap_free(cap_cur_p);
#else
   euid = geteuid(); /* Save effective user ID for later restore */
#endif
   uid = getuid();
#ifndef HAVE_LIBCAP
   if (seteuid(uid)) /* Drop SUID: Set effective user ID to real user ID */
      err_sys("seteuid()");
#endif
}

/*
 *	set_capability -- enable or disable process capabilities
 *
 *	Inputs:
 *
 *	enable = DISABLE or ENABLE capabilities
 *
 *	Returns:
 *
 *	none
 *
 *	If we have POSIX.1e capability support this function will enable
 *	or disable the required process capability in the effective set
 *
 *	If we do not have capability support, we set the effective user ID
 *	to the saved euid to enable privs or set it to the real user ID to
 *	remove root privs.
 */
void
set_capability(cap_status enable) {
#ifdef HAVE_LIBCAP
   cap_t cap_p;
   cap_flag_value_t cap_ok;
   cap_value_t cap_list[] = {CAP_NET_RAW};

   if (!(cap_p = cap_get_proc()))
      err_sys("cap_get_proc()");

   cap_ok = CAP_CLEAR;
   cap_get_flag(cap_p, cap_list[0], CAP_PERMITTED, &cap_ok);
   if (cap_ok == CAP_CLEAR && enable)
      return; /* Cannot enable cap if it's not in the permitted set */
   cap_set_flag(cap_p, CAP_EFFECTIVE, sizeof(cap_list)/sizeof(cap_list[0]),
                cap_list, enable?CAP_SET:CAP_CLEAR);
   if (cap_set_proc(cap_p) < 0)
      err_sys("cap_set_proc()");
   cap_free(cap_p);
#else
   if (seteuid(enable ? euid : getuid()))
      err_sys("seteuid()");
#endif
}


/*
 *	drop_capabilities -- Permanently drop all capabilities
 *
 *	Inputs:
 *
 *	none
 *
 *	Returns:
 *
 *	none
 *
 *	This function permanently drops all process capabilities.
 *
 *	If we have POSIX.1e capabilities support, all capabilities are removed
 *	from both effective and permitted sets.
 *
 *	If we do not have capability support, we set the user ID to the real
 *	user ID in a way that makes it impossible for the program to regain
 *	root privs.
 */
void
drop_capabilities(void) {
#ifdef HAVE_LIBCAP
   cap_t cap;

   cap = cap_init(); /* Create capability state with all flags cleared */
   if (cap_set_proc(cap) < 0)
      err_sys("cap_set_proc()");
   cap_free(cap);
#else
   if (setuid(getuid()))
      err_sys("setuid()");
#endif
}

/*
 *      name_to_id -- Return id associated with given name
 *
 *      Inputs:
 *
 *      name            The name to find in the map
 *      id_name_map     Pointer to the id-to-name map
 *
 *      Returns:
 *
 *      The id associated with the name if an association is found in the
 *      map, otherwise -1.
 *
 *      This function uses a sequential search through the map to find the
 *      ID and associated name.  This is OK when the map is relatively small,
 *      but could be time consuming if the map contains a large number of
 *      entries.
 *
 *      The search is case-blind.
 */
int
name_to_id(const char *name, const id_name_map map[]) {
   int found = 0;
   int i = 0;

   if (map == NULL)
      return -1;

   while (map[i].id != -1) {
      if ((str_ccmp(name, map[i].name)) == 0) {
         found = 1;
         break;
      }
      i++;
   }

   if (found)
      return map[i].id;
   else
      return -1;
}

/*
 *      str_ccmp  -- Case-blind string comparison
 *
 *      Inputs:
 *
 *      s1 -- The first input string
 *      s2 -- The second input string
 *
 *      Returns:
 *
 *      An integer indicating whether s1 is less than (-1), the same as (0),
 *      or greater than (1) s2.
 *
 *      This function performs the same function, and takes the same arguments
 *      as the common library function strcasecmp.  This function is used
 *      instead because strcasecmp is not portable.
 */
int
str_ccmp(const char *s1, const char *s2) {
   int c1, c2;

   for (;; s1++, s2++) {
      c1 = tolower((unsigned char)*s1);
      c2 = tolower((unsigned char)*s2);

      if (c1 > c2)
         return 1;
      if (c1 < c2)
         return -1;
      if (c1 == 0 && c2 == 0)
         return 0;
   }
}
