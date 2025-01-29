/*
 * arp-scan is Copyright (C) 2005-2025 Roy Hills
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
 * link-bpf.c -- BPF link layer functions for arp-scan
 *
 * Author:	Roy Hills
 * Date:	1 July 2006
 *
 * Description:
 *
 * This contains the link layer functions using the BPF (Berkeley
 * Packet Filter) implementation.  BPF is typically used on BSD systems such
 * as FreeBSD See bpf(4) on a FreeBSD system for details.
 *
 */

#include "arp-scan.h"

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
   struct sockaddr_dl *sdl = NULL;
   unsigned char *p;
   unsigned char *buf;
   size_t len;
   int mib[] = {CTL_NET, PF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, 0};
   /*
    * Use sysctl to obtain interface list.
    * We first call sysctl with the 3rd arg set to NULL to obtain the
    * required length, then malloc the buffer and call sysctl again to get
    * the data.
    */
   if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
      err_sys("sysctl");

   buf = Malloc(len);

   if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
      err_sys("sysctl");
   /*
    * Go through all the interfaces in the list until we find the one that
    * corresponds to the device we are using.
    */
   for (p = buf; p < buf + len; p += ifm->ifm_msglen) {
      ifm = (struct if_msghdr *)p;
   /*
    * Skip this message if the version isn't what we expect.
    */
      if (ifm->ifm_version != RTM_VERSION)
         continue;
      sdl = (struct sockaddr_dl *)(ifm + 1);

      if (ifm->ifm_type != RTM_IFINFO || (ifm->ifm_addrs & RTA_IFP) == 0)
         continue;

      if (sdl->sdl_family != AF_LINK || sdl->sdl_nlen == 0)
         continue;

      if ((memcmp(sdl->sdl_data, if_name, sdl->sdl_nlen)) == 0)
         break;
   }

   if (p >= buf + len)
      err_msg("Could not get hardware address for interface %s", if_name);

   memcpy(hw_address, sdl->sdl_data + sdl->sdl_nlen, ETH_ALEN);
   free(buf);
}
