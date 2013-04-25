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

#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#endif

#include "arp-scan.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif

/* OpenBSD needs sys/param.h */
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif

static char const rcsid[] = "$Id$";   /* RCS ID for ident(1) */

/*
 *	Link layer handle structure for BPF.
 *	This is typedef'ed as link_t.
 */
typedef struct link_handle {
   int fd;		/* Socket file descriptor */
   char device[16];
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
   char dev_file[16];	/* /dev/bpfxxx */
   struct ifreq ifr;
   int i;

   handle = Malloc(sizeof(*handle));
   memset(handle, '\0', sizeof(*handle));

   for (i=0; i<32; i++) {	/* The limit of 32 is arbitary */
      snprintf(dev_file, sizeof(dev_file), "/dev/bpf%d", i);
      handle->fd = open(dev_file, O_WRONLY);
      if (handle->fd != -1 || errno != EBUSY)
         break;
   }

   if (handle->fd == -1) {
      free(handle);
      return NULL;
   }

   memset(&ifr, '\0', sizeof(ifr));
   strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

   if ((ioctl(handle->fd, BIOCSETIF, &ifr)) < 0) {
      free(handle);
      return NULL;
   }

/* Set "header complete" flag */
#ifdef BIOCSHDRCMPLT
   i = 0;
   if (ioctl(handle->fd, BIOCSHDRCMPLT, &i) < 0) {
      free(handle);
      return NULL;
   }
#endif

   strlcpy(handle->device, device, sizeof(handle->device));
   
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
   struct if_msghdr *ifm;
   struct sockaddr_dl *sdl=NULL;
   unsigned char *p;
   unsigned char *buf;
   size_t len;
   int mib[] = { CTL_NET, PF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, 0 };
   link_t *handle;

   handle = link_open(if_name);
/*
 *	Use sysctl to obtain interface list.
 *	We first call sysctl with the 3rd arg set to NULL to obtain the
 *	required length, then malloc the buffer and call sysctl again to get
 *	the data.
 */
   if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
      err_sys("sysctl");

   buf = Malloc(len);

   if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
      err_sys("sysctl");
/*
 *	Go through all the interfaces in the list until	we find the one that
 *	corresponds to the device we are using.
 */
   for (p = buf; p < buf + len; p += ifm->ifm_msglen) {
      ifm = (struct if_msghdr *)p;
      sdl = (struct sockaddr_dl *)(ifm + 1);

      if (ifm->ifm_type != RTM_IFINFO || (ifm->ifm_addrs & RTA_IFP) == 0)
         continue;

      if (sdl->sdl_family != AF_LINK || sdl->sdl_nlen == 0)
         continue;

      if ((memcmp(sdl->sdl_data, handle->device, sdl->sdl_nlen)) == 0)
         break;
   }

   if (p >= buf + len)
      err_msg("Could not get hardware address for interface %s",
              handle->device);

   link_close(handle);

   memcpy(hw_address, sdl->sdl_data + sdl->sdl_nlen, ETH_ALEN);
   free(buf);
}

/*
 *	Use rcsid to prevent the compiler optimising it away.
 */
void link_use_rcsid(void) {
   fprintf(stderr, "%s\n", rcsid);      /* Use rcsid to stop compiler optimising away */
}
