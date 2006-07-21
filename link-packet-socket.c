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

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

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
   link_t *handle;

   handle = Malloc(sizeof(*handle));
   memset(handle, '\0', sizeof(*handle));
   if ((handle->fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
      free(handle);
      return NULL;
   }
   strncpy(handle->ifr.ifr_name, device, sizeof(handle->ifr.ifr_name));
   if ((ioctl(handle->fd, SIOCGIFINDEX, &(handle->ifr))) != 0)
      err_sys("ioctl");
   handle->sll.sll_family = PF_PACKET;
   handle->sll.sll_ifindex = handle->ifr.ifr_ifindex;
   handle->sll.sll_halen = ETH_ALEN;
   
   return handle;
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
   ssize_t nbytes;

   nbytes = sendto(handle->fd, buf, buflen, 0,
                   (struct sockaddr *)&(handle->sll), sizeof(handle->sll));
   return nbytes;
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
   if (handle != NULL) {
      if (handle->fd != 0)
         close(handle->fd);
      free(handle);
   }
}

/*
 *      get_hardware_address    -- Get the Ethernet MAC address associated
 *                                 with the given device.
 *      Inputs:
 *
 *      handle		The link layer handle
 *      hw_address	(output) the Ethernet MAC address
 *
 *      Returns:
 *
 *      None
 */
void
get_hardware_address(link_t *handle, unsigned char hw_address[]) {

/* Obtain hardware address for specified interface */
   if ((ioctl(handle->fd, SIOCGIFHWADDR, &(handle->ifr))) != 0)
      err_sys("ioctl");

   memcpy(hw_address, handle->ifr.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);
}

/*
 *      set_hardware_address    -- Set the Ethernet MAC address associated
 *                                 with the given device.
 *      Inputs:
 *
 *      handle		The link layer handle
 *      hw_address      (output) the Ethernet MAC address
 *
 *      Returns:
 *
 *      None.
 */
void
set_hardware_address(link_t *handle, unsigned char hw_address[]) {

   memcpy(handle->ifr.ifr_ifru.ifru_hwaddr.sa_data, hw_address, ETH_ALEN);

/* Set hardware address for specified interface */
   if ((ioctl(handle->fd, SIOCSIFHWADDR, &(handle->ifr))) != 0)
      err_sys("ioctl");
}

/*
 *      get_source_ip   -- Get address and mask associated with given interface
 *
 *      Inputs:
 *
 *      handle		The link level handle
 *      ip_addr		(output) The IP Address associated with the device
 *
 *      Returns:
 *
 *      Zero on success, or -1 on failure.
 */
int
get_source_ip(link_t *handle, uint32_t *ip_addr) {
   struct sockaddr_in sa_addr;

/* Obtain IP address for specified interface */
   if ((ioctl(handle->fd, SIOCGIFADDR, &(handle->ifr))) != 0) {
      warn_sys("ioctl");
      return -1;
   }
   memcpy(&sa_addr, &(handle->ifr.ifr_ifru.ifru_addr), sizeof(sa_addr));
   *ip_addr = sa_addr.sin_addr.s_addr;

   return 0;
}


/*
 *	Use rcsid to prevent the compiler optimising it away.
 */
void link_use_rcsid(void) {
   fprintf(stderr, "%s\n", rcsid);      /* Use rcsid to stop compiler optimising away */
}
