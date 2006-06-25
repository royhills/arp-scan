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
 * $Id$
 *
 * arp-scan.h -- Header file for ARP scanner
 *
 * Author:	Roy Hills
 * Date:	11 October 2005
 *
 */

/* Includes */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#else
#error This program requires the ANSI C Headers
#endif

#include <sys/types.h>

#ifdef __CYGWIN__
#include <windows.h>	/* Include windows.h if compiling under Cygwin */
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
/* Include getopt.h for the sake of getopt_long.
   We don't need the declaration of getopt, and it could conflict
   with something from a system header file, so effectively nullify that.  */
#define getopt getopt_loser
#include "getopt.h"
#undef getopt
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>	/* Posix regular expression support */
#endif

#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#include "hash.h"

/* Defines */

#define MAXLINE 255			/* Max line length for input files */
#define MAXIP 65515			/* Max IP data size = 64k - 20 */
#define SYSLOG 1			/* Use syslog if defined */
#define SYSLOG_FACILITY LOG_USER	/* Syslog facility to use */
#define REALLOC_COUNT 1000		/* Entries to realloc at once */
#define DEFAULT_BANDWIDTH 256000	/* Default bandwidth in bits/sec */
#define PACKET_OVERHEAD 18		/* Size of Ethernet header */ 
#define MINIMUM_FRAME_SIZE 46           /* Minimum data size for layer 2 */
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
#define OUIFILENAME "oui.txt"		/* Default OUI filename */
#define IABFILENAME "iab.txt"		/* Default IAB filename */
#define DEFAULT_ARP_OP ARPOP_REQUEST	/* Default ARP operation */
#define DEFAULT_ARP_HRD ARPHRD_ETHER	/* Default ARP hardware type */
#define DEFAULT_ARP_PRO ETH_P_IP	/* Default ARP protocol */
#define DEFAULT_ARP_HLN 6		/* Default hardware length */
#define DEFAULT_ARP_PLN 4		/* Default protocol length */
#define DEFAULT_ETH_PRO	ETH_P_ARP	/* Default Ethernet protocol */

/* Structures */

typedef union {
   struct in_addr v4;
   struct in6_addr v6;
   struct ether_addr l2;
} ip_address;

typedef struct {
   unsigned n;			/* Ordinal number for this entry */
   unsigned timeout;		/* Timeout for this host in us */
   ip_address addr;		/* Host IP address */
   struct timeval last_send_time; /* Time when last packet sent to this addr */
   unsigned short num_sent;	/* Number of packets sent */
   unsigned short num_recv;	/* Number of packets received */
   unsigned char live;		/* Set when awaiting response */
} host_entry;

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

void err_sys(const char *, ...);
void warn_sys(const char *, ...);
void err_msg(const char *, ...);
void warn_msg(const char *, ...);
void info_syslog(const char *, ...);
void err_print(int, int, const char *, va_list);
void usage(int);
void add_host_pattern(const char *, unsigned);
void add_host(const char *, unsigned);
int send_packet(int, host_entry *, struct timeval *);
void recvfrom_wto(int, unsigned char *, int, struct sockaddr *, int);
void remove_host(host_entry **);
void timeval_diff(const struct timeval *, const struct timeval *,
                  struct timeval *);
host_entry *find_host(host_entry **, ip_address *,
                      const unsigned char *, int);
void display_packet(int, const unsigned char *, host_entry *, ip_address *);
void advance_cursor(void);
void dump_list(void);
void print_times(void);
void initialise(void);
void clean_up(void);
void arp_scan_version(void);
char *make_message(const char *, ...);
char *printable(const unsigned char*, size_t);
void callback(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_options(int, char *[]);
ip_address *get_host_address(const char *, int, ip_address *, char **);
const char *my_ntoa(ip_address);
/* Wrappers */
int Gettimeofday(struct timeval *);
void *Malloc(size_t);
void *Realloc(void *, size_t);
unsigned long int Strtoul(const char *, int);
/* The following functions are just to prevent rcsid being optimised away */
void wrappers_use_rcsid(void);
void error_use_rcsid(void);
void utils_use_rcsid(void);
int get_source_ip(char *, uint32_t *);
int get_hardware_address(char *, unsigned char []);
void set_hardware_address(char *, unsigned char []);
void marshal_arp_pkt(unsigned char *, arp_ether_ipv4 *, size_t *);
void unmarshal_arp_pkt(const unsigned char *, arp_ether_ipv4 *);
unsigned char *hex2data(const char *, size_t *);
unsigned int hstr_i(const char *);
char *hexstring(const unsigned char *, size_t);
int get_ether_addr(const char *, unsigned char *);
