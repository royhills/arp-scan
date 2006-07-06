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
 * link-bpf.c -- BPF link layer send functions for arp-scan
 *
 * Author:	Roy Hills
 * Date:	1 July 2006
 *
 * Description:
 *
 * This contains the link layer sending functions using the BPF (Berkeley
 * Packet Filter) implementation.  BPF is typically used on BSD systems such
 * as FreeBSD See bpf(4) on a FreeBSD system for details.
 *
 */

#include "arp-scan.h"

static char const rcsid[] = "$Id$";   /* RCS ID for ident(1) */

/*
 *	Link layer handle structure for BPF.
 *	This is typedef'ed as link_t.
 */
struct link_handle {
   int fd;		/* Socket file descriptor */
   char device[16];
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
link_open(const char *device, int eth_pro, const unsigned char *target_mac) {
   link_t *handle;
   char dev_file[32];
   struct ifreq ifr;
   int i;

   handle = Malloc(sizeof(*handle));
   memset(handle, '\0', sizeof(*handle));

   for (i=0; i<32; i++) {
      snprintf(file, sizeof(file), "/dev/bpf%d", i);
      handle->fd = open(file, O_WRONLY);
      if (handle->fd != -1 || errno != EBUSY)
         break;
   }

   if (handle->fd == -1) {
      free(handle);
      return NULL;
   }

   memset(&ifr, '\0', sizeof(ifr));
   strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

   if ((ioctl(handle->fd, BIOCSETIF, &ifr)) < 0) {
      free(handle);
      return NULL;
   }

#ifdef BIOCSHDRCMPLT
   i = 1;
   if (ioctl(e->fd, BIOCSHDRCMPLT, &i) < 0) {
      free(handle);
      return NULL;
   }
#endif

   strncpy(handle->device, device, sizeof(handle->device));
   
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

   nbytes = write(handle->fd, buf, buflen);
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
   return 0;
}


/*
 *	Use rcsid to prevent the compiler optimising it away.
 */
void link_use_rcsid(void) {
   fprintf(stderr, "%s\n", rcsid);      /* Use rcsid to stop compiler optimising away */
}
