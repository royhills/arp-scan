/*
 * ARP Scan is Copyright (C) 2005-2025 Roy Hills
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

/* C89 standard headers */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>

/* C99 standard headers */
#include <stdint.h>

/* headers first defined in POSIX-1 issue 1 */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SEARCH_H
#include <search.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/* headers first defined in POSIX.1 issue 4 */
#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* headers first defined in POSIX.1 issue 6 */
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/* Other system headers */

#ifdef HAVE_PCAP_H
#include <pcap.h>	/* libpcap */
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef ARP_PCAP_DLPI
#ifdef HAVE_SYS_BUFMOD_H
#include <sys/bufmod.h>
#endif
#endif

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

/* Mersenne Twister random number generator prototypes */
#include "mt19937ar.h"

/* OpenBSD strlcpy prototype */
#ifndef HAVE_STRLCPY
#include "strlcpy.h"
#endif

/* Include the system getopt.h if getopt_long_only() is supported. Otherwise
 * include our replacement my_getopt.h */
#ifdef HAVE_GETOPT_LONG_ONLY
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#else
#include "my_getopt.h"
#endif

/* libpcap POSIX-1e capabilities support */
#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

/* Defines */

#define MAXLINE 255			/* Max line length for input files */
#define MAX_FRAME 2048			/* Maximum allowed frame size */
#define REALLOC_COUNT 1000		/* Entries to realloc at once */
#define DEFAULT_BANDWIDTH 256000	/* Default bandwidth in bits/sec */
#define PACKET_OVERHEAD 18		/* layer 2 overhead (6+6+2 + 4) */
#define MINIMUM_FRAME_SIZE 46           /* Minimum layer 2 date size */
#define DEFAULT_BACKOFF_FACTOR 1.5      /* Default timeout backoff factor */
#define DEFAULT_RETRY 2                 /* Default number of retries */
#define DEFAULT_TIMEOUT 500             /* Default per-host timeout in ms */
#define SNAPLEN 64			/* 14 (ether) + 28 (ARP) + extra */
#define PROMISC 0			/* Promiscuous mode 0=off, 1=on */
#define TO_MS 1000			/* Timeout for pcap_set_timeout() */
#define OPTIMISE 1			/* Optimise pcap filter */
#define ARPHRD_ETHER 1			/* Ethernet ARP type */
#define ARPOP_REQUEST 1			/* ARP Request */
#define ARPOP_REPLY 2			/* ARP Reply */
#define ETHER_HDR_SIZE 14		/* Size of Ethernet frame header in bytes */
#define ARP_PKT_SIZE 28			/* Size of ARP Packet in bytes */
#define ETH_ALEN 6			/* Octets in one ethernet addr */
#define ETH_P_IP 0x0800			/* Internet Protocol packet */
#define ETH_P_ARP 0x0806		/* Address Resolution packet */
#define OUIFILENAME "ieee-oui.txt"	/* Default IEEE OUI filename */
#define MACFILENAME "mac-vendor.txt"	/* Default MAC/Vendor filename */
#define DEFAULT_ARP_OP ARPOP_REQUEST	/* Default ARP operation */
#define DEFAULT_ARP_HRD ARPHRD_ETHER	/* Default ARP hardware type */
#define DEFAULT_ARP_PRO ETH_P_IP	/* Default ARP protocol */
#define DEFAULT_ARP_HLN 6		/* Default hardware length */
#define DEFAULT_ARP_PLN 4		/* Default protocol length */
#define DEFAULT_ETH_PRO	ETH_P_ARP	/* Default Ethernet protocol */
#define FRAMING_ETHERNET_II 0		/* Standard Ethernet-II Framing */
#define FRAMING_LLC_SNAP 1		/* 802.3 with LLC/SNAP */
#define OPT_WRITEPKTTOFILE 256		/* --writepkttofile option */
#define OPT_READPKTFROMFILE 257		/* --readpktfromfile option */
#define OPT_RANDOMSEED 258		/* --randomseed option */
#define OPT_EXCLUDEBROADCAST 259	/* --exclude-broadcast option */
#define HASH_TABLE_SIZE 70000		/* Max size of MAC/Vendor hash table */
#define DEFAULT_RETRY_SEND 20		/* Default no. of send packet retries */
#define DEFAULT_RETRY_SEND_INTERVAL 5000  /* Default interval between send
                                        * packet retries in microseconds */
#define NUMFIELDS 12			/* Number of output fields */

/* Structures */

typedef struct {
   unsigned timeout;		/* Timeout for this host in us */
   struct in_addr addr;		/* Host IP address */
   struct timeval last_send_time; /* Time when last packet sent to this addr */
   unsigned short num_sent;	/* Number of packets sent */
   unsigned short num_recv;	/* Number of packets received */
   unsigned char live;		/* Set when awaiting response */
} host_entry;

/* Ethernet frame header */
typedef struct {
   uint8_t dest_addr[ETH_ALEN];	/* Destination hardware address */
   uint8_t src_addr[ETH_ALEN];	/* Source hardware address */
   uint16_t frame_type;		/* Ethernet frame type */
} ether_hdr;

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

/* name to ID lookup map */
typedef struct {
   int id;
   const char *name;
} id_name_map;

/* output format */
enum format_type {
   FORMAT_INVALID,
   FORMAT_STRING,
   FORMAT_FIELD
};

typedef struct format_element {
        struct format_element *next;
        enum format_type type;
        int width;
        char *data;
} format_element;

/* POSIX.1e Capability status */
typedef enum {
   DISABLE = 0,
   ENABLE
} cap_status;

/* Functions - grouped by source file and listed in alphabetical order */

/* arp-scan.c */
void add_host(const char *, unsigned, int);
void add_host_pattern(const char *, unsigned);
int add_mac_vendor(const char *);
void advance_cursor(void);
void arp_scan_version(void);
void callback(u_char *, const struct pcap_pkthdr *, const u_char *);
void clean_up(pcap_t *);
void display_packet(host_entry *, arp_ether_ipv4 *, const unsigned char *,
                    size_t, int, int, ether_hdr *, const struct pcap_pkthdr *);
void dump_list(void);
host_entry *find_host(host_entry **, struct in_addr *);
struct in_addr *get_host_address(const char *, struct in_addr *, char **);
char *get_host_name(const struct in_addr, char **);
char *get_mac_vendor_filename(const char *, const char *, const char *);
int get_source_ip(const char *, struct in_addr *);
void marshal_arp_pkt(unsigned char *, ether_hdr *, arp_ether_ipv4 *, size_t *,
                     const unsigned char *, size_t);
const char *my_ntoa(struct in_addr);
void process_options(int, char *[]);
void recvfrom_wto(int, int, pcap_t *);
void remove_host(host_entry **);
int send_packet(pcap_t *, host_entry *, struct timeval *);
int unmarshal_arp_pkt(const unsigned char *, size_t, ether_hdr *,
                      arp_ether_ipv4 *, unsigned char *, size_t *, int *);
void usage(void);

/* error.c */
void err_msg(const char *, ...);
void err_print(int, const char *, va_list);
void err_sys(const char *, ...);
void warn_msg(const char *, ...);
void warn_sys(const char *, ...);

/* format.c */
format_element *format_parse(const char *);

/* link-{bpf,packet-socket,dlpi}.c */
void get_hardware_address(const char *, unsigned char []);

/* utils.c */
void drop_capabilities(void);
char *dupstr(const char *);
int get_ether_addr(const char *, unsigned char *);
unsigned char *hex2data(const char *, size_t *);
char *hexstring(const unsigned char *, size_t);
unsigned int hstr_i(const char *);
void limit_capabilities(void);
char *make_message(const char *, ...);
char *my_lookupdev(char *);
int name_to_id(const char *, const id_name_map[]);
void set_capability(cap_status);
int str_ccmp(const char *, const char *);
unsigned str_to_bandwidth(const char *);
unsigned str_to_interval(const char *);
void timeval_diff(const struct timeval *, const struct timeval *,
                  struct timeval *);

/* wrappers.c */
int Gettimeofday(struct timeval *);
void *Malloc(size_t);
void *Realloc(void *, size_t);
long int Strtol(const char *, int);
unsigned long int Strtoul(const char *, int);
