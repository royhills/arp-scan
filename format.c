/*
 * The ARP Scanner (arp-scan) is Copyright (C) 2005-2022 Roy Hills
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
 * Date: 24 October 2022
 *
 * This file contains output format functions, which were adapted
 * from the dpkg Debian package formatting functions in pkg-format.c.
 */

#include "arp-scan.h"

static format_element *
format_element_new(void) {
   format_element *buf;

   buf = Malloc(sizeof(*buf));
   buf->type = FORMAT_INVALID;
   buf->next = NULL;
   buf->data = NULL;
   buf->width = 0;

   return buf;
}

static void
parsefield(format_element *node, const char *fmt, const char *fmtend) {

   int len;
   const char *ws;

   len = fmtend - fmt + 1;

   ws = memchr(fmt, ';', len);
   if (ws) {
      char *endptr;
      long w;

      errno = 0;
      w = strtol(ws + 1, &endptr, 0);
      if (endptr[0] != '}') {
         err_msg("ERROR: incorrect show format: invalid character '%c' in field width", *endptr);
      }
      if (w < INT_MIN || w > INT_MAX || errno == ERANGE) {
         err_msg("ERROR: incorrect show format: field width is out of range");
      }

      node->width = w;
      len = ws - fmt;
   }

   node->type = FORMAT_FIELD;
   node->data = Malloc(len + 1);
   memcpy(node->data, fmt, len);
   node->data[len] = '\0';
}

static void
parsestring(format_element *node, const char *fmt, const char *fmtend) {

   int len;
   char *write;

   len = fmtend - fmt + 1;

   node->type = FORMAT_STRING;
   node->data = write = Malloc(len + 1);

   while (fmt <= fmtend) {
      if (*fmt == '\\') {
         fmt++;
         switch (*fmt) {
            case 'n':
               *write = '\n';
               break;
            case 't':
               *write = '\t';
               break;
            case 'r':
               *write = '\r';
               break;
            case '\\':
            default:
               *write = *fmt;
               break;
         }
      } else {
         *write = *fmt;
      }
      write++;
      fmt++;
   }
   *write = '\0';
}

void
format_free(format_element *head) {

   format_element *node;

   while (head) {
      node = head;
      head = node->next;

      free(node->data);
      free(node);
   }
}


format_element *
format_parse(const char *fmt) {

   format_element *head, *node;
   const char *fmtend;

   head = node = NULL;

   while (*fmt) {
      if (node)
         node = node->next = format_element_new();
      else
         head = node = format_element_new();

      if (fmt[0] == '$' && fmt[1] == '{') {	/* Field starting ${ */
         fmtend = strchr(fmt, '}');	/* Check for closing brace */
         if (!fmtend) {
            err_msg("ERROR: incorrect show format: missing closing brace");
            format_free(head);
            return NULL;
         }
         parsefield(node, fmt + 2, fmtend - 1);
         fmt = fmtend + 1;
      } else {	/* Not a field so presumably a string */
         fmtend = fmt;
         do {
            fmtend += 1;
            fmtend = strchrnul(fmtend, '$');	// XXXX GNU Extension XXXX
         } while (fmtend[0] && fmtend[1] != '{');

         parsestring(node, fmt, fmtend - 1);
         fmt = fmtend;
      }
   }

   if (!head)
      err_msg("ERROR: output format may not be empty string");

   return head;
}
