/*
 * The ARP Scanner (arp-scan) is Copyright (C) 2005-2013 Roy Hills,
 * NTA Monitor Ltd.
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

/*
 *	Link layer handle structure for packet socket.
 *	This is typedef'ed as link_t.
 */
typedef struct link_handle {
   int fd;		/* Socket file descriptor */
   struct ifreq ifr;
   struct sockaddr_ll sll;
} link_t;

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
static link_t *
link_open(const char *device) {
   link_t *handle;

   handle = Malloc(sizeof(*handle));
   memset(handle, '\0', sizeof(*handle));
   if ((handle->fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
      free(handle);
      return NULL;
   }
   strlcpy(handle->ifr.ifr_name, device, sizeof(handle->ifr.ifr_name));
   if ((ioctl(handle->fd, SIOCGIFINDEX, &(handle->ifr))) != 0)
      err_sys("ioctl");
   handle->sll.sll_family = PF_PACKET;
   handle->sll.sll_ifindex = handle->ifr.ifr_ifindex;
   handle->sll.sll_halen = ETH_ALEN;
   
   return handle;
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
static void
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
 *      if_name		The name of the network interface
 *      hw_address	(output) the Ethernet MAC address
 *
 *      Returns:
 *
 *      None
 */
void
get_hardware_address(const char *if_name, unsigned char hw_address[]) {
   link_t *handle;

   handle = link_open(if_name);

/* Obtain hardware address for specified interface */
   if ((ioctl(handle->fd, SIOCGIFHWADDR, &(handle->ifr))) != 0)
      err_sys("ioctl");

   link_close(handle);

   memcpy(hw_address, handle->ifr.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);
}
