/*
 * The ARP Scanner (arp-scan) is Copyright (C) 2005-2007 Roy Hills,
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
 * link-dlpi.c -- DLPI link layer send functions for arp-scan
 *
 * Author:	Roy Hills
 * Date:	22 July 2006
 *
 * Description:
 *
 * This contains the link layer sending functions using the DLPI (Data Link
 * Provider Interface) implementation.  DLPI is typically used on SysV systems
 * such as Solaris.
 *
 */

#include "arp-scan.h"

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif

#ifdef HAVE_SYS_DLPI_H
#include <sys/dlpi.h>
#endif

#ifdef HAVE_SYS_DLPIHDR_H
#include <sys/dlpihdr.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

/* Neal Nuckolls' sample code defines MAXDLBUF as 8192 longwords, but we use
 * unsigned char for our buffers and so must multiply by four */
#define MAXDLBUF 8192*4

static char const rcsid[] = "$Id$";   /* RCS ID for ident(1) */

/*
 *	Link layer handle structure for DLPI.
 *	This is typedef'ed as link_t.
 */
struct link_handle {
   int fd;
   int sap_first;
   struct ifreq ifr;
};

#if defined(DLIOCRAW) || defined(HAVE_SYS_DLPIHDR_H)
static int
strioctl(int fd, int cmd, int len, char *dp) {
   struct strioctl str;

   str.ic_cmd = cmd;
   str.ic_timout = INFTIM;
   str.ic_len = len;
   str.ic_dp = dp;

   if (ioctl(fd, I_STR, &str) < 0)
      return -1;

   return str.ic_len;
}
#endif

#ifdef HAVE_SYS_DLPIHDR_H
#define ND_BASE ('N' << 8)
#define ND_GET (ND_BASE + 0)
static int
link_match_ppa(link_t *handle, const char *device) {
   char *p;
   char dev[16];
   char buf[256];

   int len;
   int ppa;

   strlcpy(buf, "dl_ifnames", sizeof(buf));

   if ((len = strioctl(handle->fd, ND_GET, sizeof(buf), buf)) < 0)
      return -1;

   for (p = buf; p < buf + len; p += strlen(p) + 1) {
      ppa = -1;
      if (sscanf(p, "%s (PPA %d)\n", dev, &ppa) != 2)
         break;
      if (strcmp(dev, device) == 0)
         break;
   }
   return ppa;
}
#endif

static int
dlpi_msg(int fd, union DL_primitives *dlp, int rlen, int flags, int ack,
         int alen, int size) {

   struct strbuf ctl;

   ctl.maxlen = 0;
   ctl.len = rlen;
   ctl.buf = (caddr_t)dlp;

   if (putmsg(fd, &ctl, NULL, flags) < 0)
      return -1;

   ctl.maxlen = size;
   ctl.len = 0;
   flags = 0;

   if (getmsg(fd, &ctl, NULL, &flags) < 0)
      return -1;

   if (dlp->dl_primitive != ack || ctl.len < alen)
      return -1;

   return 0;
}

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
   union DL_primitives *dlp;
   unsigned char buf[MAXDLBUF];
   char *p;
   char dev[16];
   link_t *handle;
   int ppa;

   handle = Malloc(sizeof(*handle));
   memset(handle, '\0', sizeof(*handle));

#ifdef HAVE_SYS_DLPIHDR_H
   if ((handle->fd = open("/dev/streams/dlb", O_RDWR)) < 0) {
      free(handle);
      return NULL;
   }

   if ((ppa = link_match_ppa(handle, device)) < 0) {
      link_close(handle);
      return NULL;
   }
#else
   handle->fd = -1;
   snprintf(dev, sizeof(dev), "/dev/%s", device);
   if ((p = strpbrk(dev, "0123456789")) == NULL) {
      link_close(handle);
      return NULL;
   }
   ppa = atoi(p);
   *p = '\0';

   if ((handle->fd = open(dev, O_RDWR)) < 0) {
      snprintf(dev, sizeof(dev), "/dev/%s", device);
      if ((handle->fd = open(dev, O_RDWR)) < 0) {
         link_close(handle);
         return NULL;
      }
   }
#endif
   memset(&(handle->ifr), 0, sizeof(struct ifreq));
   strlcpy(handle->ifr.ifr_name, device, sizeof(handle->ifr.ifr_name));
   dlp = (union DL_primitives *)buf;
   dlp->info_req.dl_primitive = DL_INFO_REQ;

   if (dlpi_msg(handle->fd, dlp, DL_INFO_REQ_SIZE, RS_HIPRI, DL_INFO_ACK,
                DL_INFO_ACK_SIZE, sizeof(buf)) < 0) {
      link_close(handle);
      return NULL;
   }

   handle->sap_first = (dlp->info_ack.dl_sap_length > 0);

   if (dlp->info_ack.dl_provider_style == DL_STYLE2) {
      dlp->attach_req.dl_primitive = DL_ATTACH_REQ;
      dlp->attach_req.dl_ppa = ppa;

      if (dlpi_msg(handle->fd, dlp, DL_ATTACH_REQ_SIZE, 0, DL_OK_ACK,
                   DL_OK_ACK_SIZE, sizeof(buf)) < 0) {
         link_close(handle);
         return NULL;
      }
   }
   memset(&dlp->bind_req, 0, DL_BIND_REQ_SIZE);
   dlp->bind_req.dl_primitive = DL_BIND_REQ;
#ifdef DL_HP_RAWDLS
   dlp->bind_req.dl_sap = 24;      /* from HP-UX DLPI programmers guide */
   dlp->bind_req.dl_service_mode = DL_HP_RAWDLS;
#else
   dlp->bind_req.dl_sap = DL_ETHER;
   dlp->bind_req.dl_service_mode = DL_CLDLS;
#endif
   if (dlpi_msg(handle->fd, dlp, DL_BIND_REQ_SIZE, 0, DL_BIND_ACK,
                DL_BIND_ACK_SIZE, sizeof(buf)) < 0) {
      link_close(handle);
      return NULL;
   }
#ifdef DLIOCRAW
   if (strioctl(handle->fd, DLIOCRAW, 0, NULL) < 0) {
      link_close(handle);
      return NULL;
   }
#endif
   return (handle);
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
#if defined(DLIOCRAW)
   return write(handle->fd, buf, buflen);
#else
   union DL_primitives *dlp;
   struct strbuf ctl;
   struct strbuf data;
   struct eth_hdr *eth;
   unsigned char ctlbuf[MAXDLBUF];
   int dlen;

   dlp = (union DL_primitives *)ctlbuf;
#ifdef DL_HP_RAWDATA_REQ
   dlp->dl_primitive = DL_HP_RAWDATA_REQ;
   dlen = DL_HP_RAWDATA_REQ_SIZE;
#else
   dlp->unitdata_req.dl_primitive = DL_UNITDATA_REQ;
   dlp->unitdata_req.dl_dest_addr_length = ETH_ALEN;
   dlp->unitdata_req.dl_dest_addr_offset = DL_UNITDATA_REQ_SIZE;
   dlp->unitdata_req.dl_priority.dl_min = 0;
   dlp->unitdata_req.dl_priority.dl_max = 0;
   dlen = DL_UNITDATA_REQ_SIZE;
#endif
   ctl.maxlen = 0;
   ctl.len = dlen + ETH_ALEN + sizeof(eth->eth_type);
   ctl.buf = (char *)ctlbuf;

   eth = (struct eth_hdr *)buf;

   if (handle->sap_first) {
      memcpy(ctlbuf + dlen, &eth->eth_type, sizeof(eth->eth_type));
      memcpy(ctlbuf + dlen + sizeof(eth->eth_type),
             eth->eth_dst.data, ETH_ALEN);
   } else {
      memcpy(ctlbuf + dlen, eth->eth_dst.data, ETH_ALEN);
      memcpy(ctlbuf + dlen + ETH_ALEN,
             &eth->eth_type, sizeof(eth->eth_type));
   }
   data.maxlen = 0;
   data.len = buflen;
   data.buf = (char *)buf;

   if (putmsg(handle->fd, &ctl, &data, 0) < 0)
      return -1;

   return buflen;
#endif
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
      if (handle->fd >= 0) {
         close(handle->fd);
      }
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
   union DL_primitives *dlp;
   unsigned char buf[MAXDLBUF];

   dlp = (union DL_primitives*) buf;
   dlp->physaddr_req.dl_primitive = DL_PHYS_ADDR_REQ;
   dlp->physaddr_req.dl_addr_type = DL_CURR_PHYS_ADDR;
   if (dlpi_msg(handle->fd, dlp, DL_PHYS_ADDR_REQ_SIZE, 0, DL_PHYS_ADDR_ACK,
                DL_PHYS_ADDR_ACK_SIZE, sizeof(buf)) < 0) {
      err_msg("dlpi_msg failed");
   }
   memcpy(hw_address, buf + dlp->physaddr_ack.dl_addr_offset, ETH_ALEN);
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
   int fd;
   struct sockaddr_in sa_addr;

   if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
      warn_sys("Socket");
      return -1;
   }

/* Obtain IP address for specified interface */
   if ((ioctl(fd, SIOCGIFADDR, &(handle->ifr))) != 0) {
      warn_sys("ioctl");
      return -1;
   }
   memcpy(&sa_addr, &(handle->ifr.ifr_ifru.ifru_addr), sizeof(sa_addr));
   *ip_addr = sa_addr.sin_addr.s_addr;
   close(fd);

   return 0;
}

/*
 *	Use rcsid to prevent the compiler optimising it away.
 */
void link_use_rcsid(void) {
   fprintf(stderr, "%s\n", rcsid);      /* Use rcsid to stop compiler optimising away */
}
