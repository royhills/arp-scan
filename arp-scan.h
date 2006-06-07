/*
 * The ARP Scan Engine (arp-scan-engine) is Copyright (C) 2005 Roy Hills,
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
 * $Id: arp-scan.h 7469 2006-06-02 17:32:25Z rsh $
 *
 * arp-scan.h -- Header file for ARP protocol specific scanner
 *
 * Author:	Roy Hills
 * Date:	11 October 2005
 *
 * This header file contains definitions required by only the protocol-
 * specific code.
 */

/* Includes */
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SEARCH_H
#include <search.h>
#endif

/* Defines */

#define DEFAULT_BACKOFF_FACTOR 1.5      /* Default timeout backoff factor */
#define DEFAULT_RETRY 2                 /* Default number of retries */
#define DEFAULT_TIMEOUT 100             /* Default per-host timeout in ms */
#define SNAPLEN 64			/* 14 (ether) + 28 (ARP) + extra */
#define PROMISC 0			/* Enable promiscuous mode */
#define TO_MS 0				/* Timeout for pcap_open_live() */
#define OPTIMISE 1			/* Optimise pcap filter */
#define ARPHRD_ETHER 1			/* Ethernet ARP type */
#define ARPOP_REQUEST 1			/* ARP Request */
#define ARPOP_REPLY 2			/* ARP Reply */
#define ARP_PKT_SIZE 28			/* Size of ARP Packet in bytes */
#define OUIFILENAME "oui.txt"
#define DEFAULT_ARP_OP ARPOP_REQUEST	/* Default ARP operation */
#define DEFAULT_ARP_HRD ARPHRD_ETHER	/* Default ARP hardware type */
#define DEFAULT_ARP_PRO ETH_P_IP	/* Default ARP protocol */
#define DEFAULT_ARP_HLN 6		/* Default hardware length */
#define DEFAULT_ARP_PLN 4		/* Default protocol length */
#define DEFAULT_ETH_PRO	ETH_P_ARP	/* Default Ethernet protocol */

/* Structures */

/* Ethernet ARP packet from RFC 826 */
typedef struct {
   uint16_t ar_hrd;		/* Format of hardware address */
   uint16_t ar_pro;		/* Format of protocol address */
   uint8_t ar_hln;		/* Length of hardware address */
   uint8_t ar_pln;		/* Length of protocol address */
   uint16_t ar_op;		/* ARP opcode (command) */
   uint8_t ar_sha[ETH_ALEN];	/* Sender hardware address */
   uint32_t ar_sip;		/* Sender IP address */
   uint8_t ar_tha[ETH_ALEN];	/* Target hardware address */
   uint32_t ar_tip;		/* Target IP address */
} arp_ether_ipv4;

/* Functions */

int get_source_ip(char *, uint32_t *);
int get_hardware_address(char *, unsigned char []);
void marshal_arp_pkt(unsigned char *, arp_ether_ipv4 *, size_t *);
void unmarshal_arp_pkt(const unsigned char *, arp_ether_ipv4 *);
unsigned char *hex2data(const char *, size_t *);
unsigned int hstr_i(const char *);
char *hexstring(const unsigned char *, size_t);
