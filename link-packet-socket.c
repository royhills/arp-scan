/*
 * The ARP Scanner (arp-scan) is Copyright (C) 2005-2006 Roy Hills,
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
 * link-packet-socket.c -- Packet socket link layer send functions for arp-scan
 *
 * Author:	Roy Hills
 * Date:	1 July 2006
 *
 * Description:
 *
 * This contains the link layer sending functions using the packet socket
 * implementation.  Packet socket is typically used on Linux with kernel
 * version 2.2 and above.  See packet(7) on a Linux system for details.
 *
 */

#include "arp-scan.h"

static char const rcsid[] = "$Id$";   /* RCS ID for ident(1) */

/*
 *	Link layer handle structure for packet socket.
 *	This is typedef'ed as link_t.
 */
struct link_handle {
   int fd;		/* Socket file descriptor */
   struct ifreq ifr;
   struct sockaddr_ll sll;
};

/*
 *	link_open -- Open the specified link-level device
 *
 *	Inputs:
 *
 *	device		The name of the device to open
 *
 *	Returns:
 *
 *	A pointer to a link handle structure.
 */
link_t *
link_open(const char *device) {
   return NULL;
}

/*
 *	link_send -- Send a packet
 *
 *	Inputs:
 *
 *	handle		The handle for the link interface
 *	buf		Pointer to the data to send
 *	buflen		Number of bytes to send
 *
 *	Returns:
 *
 *	The number of bytes sent, or -1 for error.
 */
ssize_t
link_send(link_t *handle, const unsigned char *buf, size_t buflen) {
   return 0;
}

/*
 *	link_close -- Close the link
 *
 *	Inputs:
 *
 *	handle		The handle for the link interface
 *
 *	Returns:
 *
 *	None
 */
void
link_close(link_t *handle) {
}

/*
 *	Use rcsid to prevent the compiler optimising it away.
 */
void link_use_rcsid(void) {
   fprintf(stderr, "%s\n", rcsid);      /* Use rcsid to stop compiler optimising away */
}
