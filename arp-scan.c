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
 * $Id: arp-scan.c 7543 2006-06-07 06:28:04Z rsh $
 *
 * arp-scan -- The ARP Scanner
 *
 * Author:	Roy Hills
 * Date:	13 October 2005
 *
 * Usage:
 *    arp-scan [options] [host...]
 *
 * Description:
 *
 * arp-scan sends the specified ARP packet to the specified hosts
 * and displays any responses received.
 *
 * The ARP protocol is defined in RFC 826 Ethernet Address Resolution Protocol
 * 
 */

#include "ether-scan-engine.h"
#include "arp-scan.h"

static char const rcsid[] = "$Id: arp-scan.c 7543 2006-06-07 06:28:04Z rsh $";   /* RCS ID for ident(1) */

/* Global variables */
unsigned retry = DEFAULT_RETRY;		/* Number of retries */
unsigned timeout = DEFAULT_TIMEOUT;	/* Per-host timeout */
float backoff_factor = DEFAULT_BACKOFF_FACTOR;	/* Backoff factor */
int snaplen = SNAPLEN;			/* Pcap snap length */
char *if_name=NULL;			/* Interface name, e.g. "eth0" */
int quiet_flag=0;			/* Don't decode the packet */
int ignore_dups=0;			/* Don't display duplicate packets */
char const scanner_name[] = "arp-scan";
char const scanner_version[] = "1.2";

extern int verbose;	/* Verbose level */
extern int debug;	/* Debug flag */
extern host_entry *helist;	/* Array of host entries */
host_entry **helistptr;		/* Array of pointers to host entries */
extern unsigned num_hosts;		/* Number of entries in the list */
extern unsigned max_iter;		/* Max iterations in find_host() */
extern pcap_t *handle;			/* pcap handle */
extern host_entry **cursor;
extern unsigned responders;		/* Number of hosts which responded */
extern char filename[MAXLINE];
extern int filename_flag;
extern int random_flag;			/* Randomise the list */
extern int numeric_flag;		/* IP addresses only */
extern int ipv6_flag;			/* IPv6 */
extern int ether_flag;
extern unsigned bandwidth;
extern unsigned interval;

static uint32_t arp_spa;		/* Source IP address */
static int arp_spa_flag=0;		/* Source IP address specified */
static unsigned char arp_sha[ETH_ALEN];	/* Source Ethernet MAC Address */
static int arp_sha_flag=0;		/* Source MAC address specified */
static int if_index;			/* Interface index */
extern int pcap_fd;			/* pcap File Descriptor */
static size_t ip_offset;		/* Offset to IP header in pcap pkt */
static char ouifilename[MAXLINE];	/* OUI filename */
static int arp_op=DEFAULT_ARP_OP;	/* ARP Operation code */
static int arp_hrd=DEFAULT_ARP_HRD;	/* ARP hardware type */
static int arp_pro=DEFAULT_ARP_PRO;	/* ARP protocol */
static int arp_hln=DEFAULT_ARP_HLN;	/* Hardware address length */
static int arp_pln=DEFAULT_ARP_PLN;	/* Protocol address length */
static int eth_pro=DEFAULT_ETH_PRO;	/* Ethernet protocol type */
static unsigned char arp_tha[6] = {0, 0, 0, 0, 0, 0};
static unsigned char target_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static unsigned char *padding=NULL;
static size_t padding_len=0;

/*
 *	display_packet -- Check and display received packet
 *
 *	Inputs:
 *
 *	n		The length of the received packet in bytes.
 *			Note that this can be more or less than the IP packet
 *			size because of minimum frame sizes or snaplength
 *			cutoff respectively.
 *	packet_in	The received packet
 *	he		The host entry corresponding to the received packet
 *	recv_addr	IP address that the packet was received from
 *
 *      Returns:
 *
 *      None.
 *
 *      This should check the received packet and display details of what
 *      was received in the format: <IP-Address><TAB><Details>.
 */
void
display_packet(int n, const unsigned char *packet_in, host_entry *he,
               ip_address *recv_addr) {
   arp_ether_ipv4 arpei;
   char *msg;
   char *cp;
   char *cp2;
   const unsigned char *ucp;
   int extra_data;
   int nonzero=0;
/*
 *	Set msg to the IP address of the host entry, plus the address of the
 *	responder if different, and a tab.
 */
   msg = make_message("%s\t", my_ntoa(he->addr));
   if ((he->addr).v4.s_addr != recv_addr->v4.s_addr) {
      cp = msg;
      msg = make_message("%s(%s) ", cp, my_ntoa(*recv_addr));
      free(cp);
   }
/*
 *      Unmarshal packet buffer into ARP structure
 */
   unmarshal_arp_pkt(packet_in+ip_offset, &arpei);
/*
 *	Decode ARP packet
 */
   cp = msg;
   msg = make_message("%s%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", cp,
                      arpei.ar_sha[0], arpei.ar_sha[1],
                      arpei.ar_sha[2], arpei.ar_sha[3],
                      arpei.ar_sha[4], arpei.ar_sha[5]);
   free(cp);
/*
 *	Find OUI from hash table and add to message if quiet if not in
 *	effect.
 */
   if (!quiet_flag) {
      char *oui_string;
      ENTRY oui_entry;
      ENTRY *oui_result;

      oui_string = make_message("%.2X%.2X%.2X", arpei.ar_sha[0],
                                arpei.ar_sha[1], arpei.ar_sha[2]);
      oui_entry.key = oui_string;
      oui_result = hsearch(oui_entry, FIND);
      cp = msg;
      if (oui_result)
         msg = make_message("%s\t%s", cp, oui_result->data);
      else
         msg = make_message("%s\t%s", cp, "(Unknown)");
      free(cp);
      free(oui_string);
/*
 *	Check that any data after the ARP packet is zero.
 *	If it is non-zero, and verbose is selected, then print the padding.
 */
   ucp = packet_in+ip_offset+28;
   extra_data = n-ip_offset-28;
   if (extra_data > 0) {
      int i;
      for (i=0; i<extra_data; i++) {
         if (ucp[i] != '\0') {
            nonzero=1;
            break;
         }
      }
   }
   if (nonzero && verbose) {
      cp = msg;
      cp2 = hexstring(ucp, extra_data);
      msg = make_message("%s\tPadding=%s", cp, cp2);
      free(cp2);
      free(cp);
   }
/*
 *      If the host entry is not live, then flag this as a duplicate.
 */
      if (!he->live) {
         cp = msg;
         msg = make_message("%s (DUP: %u)", cp, he->num_recv);
         free(cp);
      }
   }	/* End if (!quiet_flag) */
/*
 *	Print the message.
 */
   printf("%s\n", msg);
   free(msg);
}

/*
 *	send_packet -- Construct and send a packet to the specified host
 *
 *	Inputs:
 *
 *	s		IP socket file descriptor
 *	he		Host entry to send to. If NULL, then no packet is sent
 *	last_packet_time	Time when last packet was sent
 *
 *      Returns:
 *
 *      The size of the packet that was sent.
 *
 *      This must construct an appropriate packet and send it to the host
 *      identified by "he" using the socket "s".
 *      It must also update the "last_send_time" field for this host entry.
 */
int
send_packet(int s, host_entry *he,
            struct timeval *last_packet_time) {
   struct sockaddr_ll sa_peer;
   unsigned char buf[MAXIP];
   size_t buflen;
   NET_SIZE_T sa_peer_len;
   arp_ether_ipv4 arpei;
/*
 *	Construct the ARP Header.
 */
   memset(&arpei, '\0', sizeof(arp_ether_ipv4));
   arpei.ar_hrd = htons(arp_hrd);
   arpei.ar_pro = htons(arp_pro);
   arpei.ar_hln = arp_hln;
   arpei.ar_pln = arp_pln;
   arpei.ar_op = htons(arp_op);
   memcpy(arpei.ar_sha, arp_sha, ETH_ALEN);
   memcpy(arpei.ar_tha, arp_tha, ETH_ALEN);
   arpei.ar_sip = arp_spa;
   if (he)
      arpei.ar_tip = he->addr.v4.s_addr;
/*
 *	Copy the required data into the output buffer "buf" and set "buflen"
 *	to the number of bytes in this buffer.
 */
   marshal_arp_pkt(buf, &arpei, &buflen);
/*
 *	Add padding if specified
 */
   if (padding != NULL) {
      memcpy(buf+buflen, padding, padding_len);
      buflen += padding_len;
   }
/*
 *	If he is NULL, just return with the packet length.
 */
   if (he == NULL)
      return buflen;
/*
 *	Check that the host is live.  Complain if not.
 */
   if (!he->live) {
      warn_msg("***\tsend_packet called on non-live host entry: SHOULDN'T HAPPEN");
      return 0;
   }
/*
 *	Set up the sockaddr_ll structure for the host.
 *	This defines the Ethernet link-layer header for the packet.
 */
   memset(&sa_peer, '\0', sizeof(sa_peer));
   sa_peer.sll_family = PF_PACKET;
   sa_peer.sll_protocol = htons(eth_pro);
   sa_peer.sll_ifindex = if_index;
   sa_peer.sll_halen = ETH_ALEN;
   memcpy(sa_peer.sll_addr, target_mac, sizeof(target_mac));
   sa_peer_len = sizeof(sa_peer);
/*
 *	Update the last send times for this host.
 */
   Gettimeofday(last_packet_time);
   he->last_send_time.tv_sec  = last_packet_time->tv_sec;
   he->last_send_time.tv_usec = last_packet_time->tv_usec;
   he->num_sent++;
/*
 *	Send the packet.
 */
   if (debug) {print_times(); printf("send_packet: #%u to host entry %u (%s) tmo %d\n", he->num_sent, he->n, my_ntoa(he->addr), he->timeout);}
   if (verbose > 1)
      warn_msg("---\tSending packet #%u to host entry %u (%s) tmo %d", he->num_sent, he->n, my_ntoa(he->addr), he->timeout);
   if ((sendto(s, buf, buflen, 0, (struct sockaddr *) &sa_peer, sa_peer_len)) < 0) {
      err_sys("sendto");
   }
   return buflen;
}

/*
 *      initialise -- Protocol-specific initialisation routine.
 *
 *      Inputs:
 *
 *      None.
 *
 *      Returns:
 *
 *      None.
 *
 *      This is called once before any packets have been sent.  It can be
 *      used to perform any required initialisation.  It does not have to
 *      do anything.
 */
void
initialise(void) {
   char errbuf[PCAP_ERRBUF_SIZE];
   struct bpf_program filter;
   char *filter_string;
   bpf_u_int32 netmask;
   bpf_u_int32 localnet;
   int datalink;
   unsigned char interface_mac[ETH_ALEN];
   int get_addr_status = 0;
/*
 *	Determine network interface to use.
 *	If the interface was specified with the --interface option then use
 *	that, otherwise if the environment variable "RMIF" exists then use
 *	that, failing that use pcap_lookupdev() to pick a suitable interface.
 */
   if (!if_name) { /* i/f not specified with --interface */
      if (!(if_name=getenv("RMIF"))) {	/* No RMIF env var */
         if (!(if_name=pcap_lookupdev(errbuf))) {
            err_msg("pcap_lookupdev: %s", errbuf);
         }
      }
   }
/*
 *	Obtain the interface index and MAC address for the selected
 *	interface, and if possible also obtain the IP address.
 */
   if_index = get_hardware_address(if_name, interface_mac);
   if (arp_sha_flag == 0)
      memcpy(arp_sha, interface_mac, ETH_ALEN);
   if (arp_spa_flag == 0) {
      get_addr_status = get_source_ip(if_name, &arp_spa);
      if (get_addr_status == -1) {
         warn_msg("WARNING: Could not obtain IP address for interface %s. "
                  "Using 0.0.0.0 for",
                  if_name);
         warn_msg("the source address, which is probably not what you want.");
         warn_msg("Either configure %s with an IP address, or manually specify"
                  " the address", if_name);
         warn_msg("with the --arpspa option.");
         memset(&arp_spa, '\0', sizeof(arp_spa));
      }
   }
/*
 *	Prepare pcap
 */
   if (!(handle = pcap_open_live(if_name, snaplen, PROMISC, TO_MS, errbuf)))
      err_msg("pcap_open_live: %s\n", errbuf);
   if ((datalink=pcap_datalink(handle)) < 0)
      err_msg("pcap_datalink: %s\n", pcap_geterr(handle));
   printf("Interface: %s, datalink type: %s (%s)\n", if_name,
          pcap_datalink_val_to_name(datalink),
          pcap_datalink_val_to_description(datalink));
   switch (datalink) {
      case DLT_EN10MB:		/* Ethernet */
         ip_offset = 14;
         break;
      case DLT_LINUX_SLL:	/* PPP on Linux */
         ip_offset = 16;
         break;
      default:
         err_msg("Unsupported datalink type");
         break;
   }
   if ((pcap_fd=pcap_fileno(handle)) < 0)
      err_msg("pcap_fileno: %s\n", pcap_geterr(handle));
   if ((pcap_setnonblock(handle, 1, errbuf)) < 0)
      err_msg("pcap_setnonblock: %s\n", errbuf);
   if (get_addr_status == 0) {
      if (pcap_lookupnet(if_name, &localnet, &netmask, errbuf) < 0) {
         memset(&localnet, '\0', sizeof(localnet));
         memset(&netmask, '\0', sizeof(netmask));
      }
   } else {	/* get_ip_address() failed, so pcap_lookupnet probably will */
      memset(&localnet, '\0', sizeof(localnet));
      memset(&netmask, '\0', sizeof(netmask));
   }
   filter_string=make_message("arp and ether dst %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                              interface_mac[0], interface_mac[1],
                              interface_mac[2], interface_mac[3],
                              interface_mac[4], interface_mac[5]);
   if (verbose)
      warn_msg("DEBUG: pcap filter string: \"%s\"", filter_string);
   if ((pcap_compile(handle, &filter, filter_string, OPTIMISE, netmask)) < 0)
      err_msg("pcap_geterr: %s\n", pcap_geterr(handle));
   free(filter_string);
   if ((pcap_setfilter(handle, &filter)) < 0)
      err_msg("pcap_setfilter: %s\n", pcap_geterr(handle));
/*
 * Create OUI hash table if quiet if not in effect.
 */
   if (!quiet_flag) {
      char *fn;	/* OUI filename */
      FILE *fp;	/* OUI file handle */
      ENTRY oui_entry;
      static const char *oui_pat_str = "([^\t]+)\t[\t ]*([^\t\r\n]+)";
      regex_t oui_pat;
      int result;
      size_t line_count;
      regmatch_t pmatch[3];
      size_t key_len;
      size_t data_len;
      char *key;
      char *data;
      char line[MAXLINE];

      if ((result=regcomp(&oui_pat, oui_pat_str, REG_EXTENDED))) {
         char reg_errbuf[MAXLINE];
         size_t errlen;
         errlen=regerror(result, &oui_pat, reg_errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 oui_pat_str, reg_errbuf);
      }
      if (*ouifilename == '\0')	/* If OUI filename not specified */
         fn = make_message("%s/%s", DATADIR, OUIFILENAME);
      else
         fn = make_message("%s", ouifilename);
/* Check access before opening the OUI file in case we are SUID root */
      if ((access(fn, R_OK)) != 0 || (fp = fopen(fn, "r")) == NULL) {
         warn_sys("WARNING: Cannot open OUI file %s", fn);
         quiet_flag = 1;	/* Don't decode OUI vendor */
      } else {
         line_count=0;
         while (fgets(line, MAXLINE, fp)) {	/* Count lines in file */
            if (line[0] != '#' && line[0] != '\n' && line[0] != '\r')
               line_count++;
         }
   
         if ((hcreate(line_count)) == 0)
            err_sys("hcreate");
         rewind(fp);
         line_count=0;
         while (fgets(line, MAXLINE, fp)) {	/* create hash table */
            if (line[0] != '#' && line[0] != '\n' && line[0] != '\r') {
               result = regexec(&oui_pat, line, 3, pmatch, 0);
               if (result == REG_NOMATCH || pmatch[1].rm_so < 0 ||
                   pmatch[2].rm_so < 0) {
                  warn_msg("WARNING: Could not parse oui: %s", line);
               } else if (result != 0) {
                  char reg_errbuf[MAXLINE];
                  size_t errlen;
                  errlen=regerror(result, &oui_pat, reg_errbuf, MAXLINE);
                  err_msg("ERROR: oui regexec failed: %s", reg_errbuf);
               } else {
                  key_len = pmatch[1].rm_eo - pmatch[1].rm_so;
                  data_len = pmatch[2].rm_eo - pmatch[2].rm_so;
                  key=Malloc(key_len+1);
                  data=Malloc(data_len+1);
                  strncpy(key, line+pmatch[1].rm_so, key_len);
                  key[key_len] = '\0';
                  strncpy(data, line+pmatch[2].rm_so, data_len);
                  data[data_len] = '\0';
                  oui_entry.key = key;
                  oui_entry.data = data;
                  if ((hsearch(oui_entry, ENTER)) == NULL)
                     err_sys("hsearch");
                  line_count++;
               }
            }
         }
         fclose(fp);
         if (verbose)
            warn_msg("DEBUG: Loaded %u OUI/Vendor entries into hash table", line_count);
      }
      free(fn);
   }
}

/*
 *      clean_up -- Protocol-specific Clean-Up routine.
 *
 *      Inputs:
 *
 *      None.
 *
 *      Returns:
 *
 *      None.
 *
 *      This is called once after all hosts have been processed.  It can be
 *      used to perform any tidying-up or statistics-displaying required.
 *      It does not have to do anything.
 */
void
clean_up(void) {
   struct pcap_stat stats;

   if ((pcap_stats(handle, &stats)) < 0)
      err_msg("pcap_stats: %s\n", pcap_geterr(handle));

   printf("%u packets received by filter, %u packets dropped by kernel\n",
          stats.ps_recv, stats.ps_drop);
   pcap_close(handle);
}

/*
 *      local_version -- Scanner-specific version function.
 *
 *      Inputs:
 *
 *      None.
 *
 *      Returns:
 *
 *      None.
 *
 *      This should output the scanner-specific version number to stderr.
 */
void
local_version(void) {
/* We use rcsid here to prevent it being optimised away */
   fprintf(stderr, "%s\n", rcsid);
}

/*
 *      local_help -- Scanner-specific help function.
 *
 *      Inputs:
 *
 *      None.
 *
 *      Returns:
 *
 *      None.
 *
 */
void
local_help(void) {
   fprintf(stderr, "\n--snap=<s> or -n <s>\tSet the pcap snap length to <s>. Default=%d.\n", SNAPLEN);
   fprintf(stderr, "\t\t\tThis specifies the frame capture length.  This\n");
   fprintf(stderr, "\t\t\tlength includes the data-link header.\n");
   fprintf(stderr, "\t\t\tThe default is normally sufficient.\n");
   fprintf(stderr, "\n--interface=<i> or -I <i> Use network interface <i>.\n");
   fprintf(stderr, "\t\t\tIf this option is not specified, the default is the\n");
   fprintf(stderr, "\t\t\tvalue of the RMIF environment variable.  If RMIF is\n");
   fprintf(stderr, "\t\t\tnot defined, then \"eth0\" is used as a last resort.\n");
   fprintf(stderr, "\t\t\tThe interface specified must be an Ethernet device.\n");
   fprintf(stderr, "\n--quiet or -q\t\tOnly display minimal output.\n");
   fprintf(stderr, "\t\t\tIf this option is specified, then only the minimum\n");
   fprintf(stderr, "\t\t\tinformation is displayed.  With this option, the\n");
   fprintf(stderr, "\t\t\tOUI file is not used.\n");
   fprintf(stderr, "\n--ignoredups or -g\tDon't display duplicate packets.\n");
   fprintf(stderr, "\t\t\tBy default, duplicate packets are displayed.\n");
   fprintf(stderr, "\n--ouifile=<o> or -O <o>\tUse OUI file <o>, default=%s/%s\n", DATADIR, OUIFILENAME);
   fprintf(stderr, "\t\t\tThis file provides the Ethernet OUI to vendor string\n");
   fprintf(stderr, "\t\t\tmapping.\n");
   fprintf(stderr, "\n--destaddr=<m> or -T <m> Send the packets to Ethernet MAC address <m>\n");
   fprintf(stderr, "\t\t\tThis sets the 48-bit destination address in the\n");
   fprintf(stderr, "\t\t\tEthernet frame header.\n");
   fprintf(stderr, "\t\t\tThe default is the broadcast address ff:ff:ff:ff:ff:ff.\n");
   fprintf(stderr, "\t\t\tMost operating systems will also respond if the ARP\n");
   fprintf(stderr, "\t\t\trequest is sent to their MAC address, or to a\n");
   fprintf(stderr, "\t\t\tmulticast address that they are listening on.\n");
   fprintf(stderr, "\n--arpsha=<m> or -u <m>\tUse <m> as the ARP source Ethernet address\n");
   fprintf(stderr, "\t\t\tThis sets the 48-bit ar$sha field in the ARP packet\n");
   fprintf(stderr, "\t\t\tThe default is the Ethernet address of the outgoing\n");
   fprintf(stderr, "\t\t\tinterface.\n");
   fprintf(stderr, "\n--arptha=<m> or -w <m>\tUse <m> as the ARP target Ethernet address\n");
   fprintf(stderr, "\t\t\tThis sets the 48-bit ar$tha field in the ARP packet\n");
   fprintf(stderr, "\t\t\tThe default is zero, because this field is not used\n");
   fprintf(stderr, "\t\t\tfor ARP request packets.\n");
   fprintf(stderr, "\n--prototype=<p> or -y <p> Set the Ethernet protocol type to <p>, default=0x%.4x.\n", DEFAULT_ETH_PRO);
   fprintf(stderr, "\t\t\tThis sets the 16-bit protocol type field in the\n");
   fprintf(stderr, "\t\t\tEthernet frame header.\n");
   fprintf(stderr, "\t\t\tSetting this to a non-default value will result in the\n");
   fprintf(stderr, "\t\t\tpacket being ignored by the target, or send to the\n");
   fprintf(stderr, "\t\t\twrong protocol stack.\n");
   fprintf(stderr, "\t\t\tThis option is probably not useful, and is only\n");
   fprintf(stderr, "\t\t\tpresent for completeness.\n");
   fprintf(stderr, "\n--arphrd=<o> or -H <o>\tUse <o> for the ARP hardware type, default=%d.\n", DEFAULT_ARP_HRD);
   fprintf(stderr, "\t\t\tThis sets the 16-bit ar$hrd field in the ARP packet.\n");
   fprintf(stderr, "\t\t\tThe normal value is 1 (ARPHRD_ETHER).  Most, but not\n");
   fprintf(stderr, "\t\t\tall, operating systems will also respond to 6\n");
   fprintf(stderr, "\t\t\t(ARPHRD_IEEE802). A few systems respond to any value.\n");
   fprintf(stderr, "\n--arppro=<o> or -p <o>\tUse <o> for the ARP protocol type, default=0x%.4x.\n", DEFAULT_ARP_PRO);
   fprintf(stderr, "\t\t\tThis sets the 16-bit ar$pro field in the ARP packet.\n");
   fprintf(stderr, "\t\t\tMost operating systems only respond to 0x0800 (IPv4)\n");
   fprintf(stderr, "\t\t\tbut some will respond to other values as well.\n");
   fprintf(stderr, "\n--arphln=<l> or -a <l>\tSet the hardware address length to <l>, default=%d.\n", DEFAULT_ARP_HLN);
   fprintf(stderr, "\t\t\tThis sets the 8-bit ar$hln field in the ARP packet.\n");
   fprintf(stderr, "\t\t\tIt sets the claimed length of the hardware address\n");
   fprintf(stderr, "\t\t\tin the ARP packet.  Setting it to any value other than\n");
   fprintf(stderr, "\t\t\tthe default will make the packet non RFC compliant.\n");
   fprintf(stderr, "\t\t\tSome operating systems may still respond to it though.\n");
   fprintf(stderr, "\t\t\tNote that the actual lengths of the ar$sha and ar$tha\n");
   fprintf(stderr, "\t\t\tfields in the ARP packet are not changed by this\n");
   fprintf(stderr, "\t\t\toption; it only changes the ar$hln field.\n");
   fprintf(stderr, "\n--arppln=<l> or -P <l>\tSet the protocol address length to <l>, default=%d.\n", DEFAULT_ARP_PLN);
   fprintf(stderr, "\t\t\tThis sets the 8-bit ar$pln field in the ARP packet.\n");
   fprintf(stderr, "\t\t\tIt sets the claimed length of the protocol address\n");
   fprintf(stderr, "\t\t\tin the ARP packet.  Setting it to any value other than\n");
   fprintf(stderr, "\t\t\tthe default will make the packet non RFC compliant.\n");
   fprintf(stderr, "\t\t\tSome operating systems may still respond to it though.\n");
   fprintf(stderr, "\t\t\tNote that the actual lengths of the ar$spa and ar$tpa\n");
   fprintf(stderr, "\t\t\tfields in the ARP packet are not changed by this\n");
   fprintf(stderr, "\t\t\toption; it only changes the ar$pln field.\n");
   fprintf(stderr, "\n--arpop=<o> or -o <o>\tUse <o> for the ARP operation, default=%d.\n", DEFAULT_ARP_OP);
   fprintf(stderr, "\t\t\tThis sets the 16-bit ar$op field in the ARP packet.\n");
   fprintf(stderr, "\t\t\tMost operating systems will only respond to the value 1\n");
   fprintf(stderr, "\t\t\t(ARPOP_REQUEST). However, some systems will respond\n");
   fprintf(stderr, "\t\t\tto other values as well.\n");
   fprintf(stderr, "\n--arpspa=<s> or -s <s>\tUse <s> as the source IP address.\n");
   fprintf(stderr, "\t\t\tThe address should be specified in dotted quad format.\n");
   fprintf(stderr, "\t\t\tThis sets the 32-bit ar$spa field in the ARP packet.\n");
   fprintf(stderr, "\t\t\tSome operating systems check this, and will only\n");
   fprintf(stderr, "\t\t\trespond if the source address is within the network\n");
   fprintf(stderr, "\t\t\tof the receiving interface.  Others don't care, and\n");
   fprintf(stderr, "\t\t\twill respond to any source address.\n");
   fprintf(stderr, "\t\t\tBy default, the outgoing interface address is used.\n");
   fprintf(stderr, "\n--padding=<p> or -A <p>\tSpecify padding after packet data.\n");
   fprintf(stderr, "\t\t\tSet the padding data to hex value <p>.  This data is\n");
   fprintf(stderr, "\t\t\tappended to the end of the ARP packet, after the data.\n");
   fprintf(stderr, "\t\t\tMost, if not all, operating systems will ignore any\n");
   fprintf(stderr, "\t\t\tPadding.  The default is no padding, although the\n");
   fprintf(stderr, "\t\t\tEthernet driver on the sending system may pad the\n");
   fprintf(stderr, "\t\t\tpacket to the minimum Ethernet frame length.\n");
}

/*
 *      local_add_host -- Protocol-specific add host routine.
 *
 *      Inputs:
 *
 *      host_name = The Name or IP address of the host.
 *      host_timeout = The initial host timeout in ms.
 *
 *      Returns:
 *
 *      0 (Zero) if this function doesn't need to do anything, or
 *      1 (One) if this function replaces the generic add_host function.
 *
 *	This function is called before the helistptr array is created, so
 *	we use the helist array directly.
 *
 *      This routine is called once for each specified host.
 *
 *      This protocol-specific add host routine can replace the generic
 *      ether-scan add-host routine if required.  If it is to replace the
 *      generic routine, then it must perform all of the add_host functions
 *      and return 1.  Otherwise, it must do nothing and return 0.
 */
int
local_add_host(const char *host_name, unsigned host_timeout) {
   return 0;
}

/*
 *	get_source_ip	-- Get address and mask associated with given interface
 *
 *	Inputs:
 *
 *	devname		The device name, e.g. "eth0"
 *	ip_address	(output) The IP Address associated with the device
 *
 *	Returns:
 *
 *	Zero on success, or -1 on failure.
 */
int
get_source_ip(char *devname, uint32_t *ip_address) {
   int sockfd;
   struct ifreq ifconfig;
   struct sockaddr_in sa_addr;

   strncpy(ifconfig.ifr_name, devname, IFNAMSIZ);

/* Create UDP socket */
   if ((sockfd=socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
      warn_sys("socket");
      return -1;
   }

/* Obtain IP address for specified interface */
   if ((ioctl(sockfd, SIOCGIFADDR, &ifconfig)) != 0) {
      warn_sys("ioctl");
      return -1;
   }
   memcpy(&sa_addr, &ifconfig.ifr_ifru.ifru_addr, sizeof(sa_addr));
   *ip_address = sa_addr.sin_addr.s_addr;

   close(sockfd);
   return 0;
}

/*
 *	get_hardware_address	-- Get the Ethernet MAC address associated
 *				   with the given device.
 *	Inputs:
 *
 *	devname		The device name, e.g. "eth0"
 *	hw_address	(output) the Ethernet MAC address
 *
 *	Returns:
 *
 *	The interface device index.
 */
int
get_hardware_address(char *devname, unsigned char hw_address[]) {
   int sockfd;
   struct ifreq ifconfig;

   strncpy(ifconfig.ifr_name, devname, IFNAMSIZ);

/* Create UDP socket */
   if ((sockfd=socket(PF_INET, SOCK_DGRAM, 0)) < 0)
      err_sys("socket");

/* Obtain hardware address for specified interface */
   if ((ioctl(sockfd, SIOCGIFHWADDR, &ifconfig)) != 0)
      err_sys("ioctl");

/* Check that device type is Ethernet */
   if (ifconfig.ifr_ifru.ifru_hwaddr.sa_family != ARPHRD_ETHER)
      err_msg("%s is not an Ethernet device", devname);

   memcpy(hw_address, ifconfig.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);

/* Obtain interface index for specified interface */
   if ((ioctl(sockfd, SIOCGIFINDEX, &ifconfig)) != 0)
      err_sys("ioctl");
   close(sockfd);

   return ifconfig.ifr_ifindex;
}

/*
 *	local_find_host -- Protocol-specific find host routine.
 *
 *	Inputs:
 *
 *	ptr	Pointer to the host entry that was found, or NULL if not found
 *      he      Pointer to the current position in the list.  Search runs
 *              backwards starting from this point.
 *      addr    The source IP address that the packet came from.
 *      packet_in The received packet data.
 *      n       The length of the received packet.
 *
 *	Returns:
 *
 *	0 (Zero) if this function doesn't need to do anything, or
 *	1 (One) if this function replaces the generic add_host function.
 *
 *	This routine is called every time a packet is received.
 *
 *	This protocol-specific find host routine can replace the generic
 *	ether-scan find-host routine if required.  If it is to replace the
 *	generic routine, then it must perform all of the find_host functions
 *	and return 1.  Otherwise, it must do nothing and return 0.
 */
int
local_find_host(host_entry **ptr, host_entry **he,
                ip_address *addr, const unsigned char *packet_in, int n) {
   host_entry **p;
   int found = 0;
   unsigned iterations = 0;     /* Used for debugging */
/*
 *      Don't try to match if host ptr is NULL.
 *      This should never happen, but we check just in case.
 */
   if (*he == NULL) {
      *ptr = NULL;
      return 1;
   }
/*
 *	Try to match against out host list.
 */
   p = he;
   do {
      iterations++;
      if (((*p)->addr.v4.s_addr == addr->v4.s_addr)) {
         found = 1;
      } else {
         if (p == helistptr) {
            p = helistptr + (num_hosts-1); /* Wrap round to end */
         } else {
            p--;
         }
      }
   } while (!found && p != he);

   if (debug) {print_times(); printf("find_host: found=%d, iterations=%u\n", found, iterations);}

   if (iterations > max_iter)
      max_iter=iterations;

   if (found)
      *ptr = *p;
   else
      *ptr = NULL;

   return 1;
}

/*
 * callback -- pcap callback function
 *
 * Inputs:
 *
 *	args		Special args (not used)
 *	header		pcap header structure
 *	packet_in	The captured packet
 *
 * Returns:
 *
 * None
 */
void
callback(u_char *args, const struct pcap_pkthdr *header,
         const u_char *packet_in) {
   arp_ether_ipv4 arpei;
   int n = header->caplen;
   ip_address source_ip;
   host_entry *temp_cursor;
/*
 *      Check that the packet is large enough to decode.
 */
   if (n < ip_offset + ARP_PKT_SIZE) {
      printf("%d byte packet too short to decode\n", n);
      return;
   }
/*
 *	Unmarshal packet buffer into ARP structure
 */
   unmarshal_arp_pkt(packet_in+ip_offset, &arpei);
/*
 *	Determine source IP address.
 */
   source_ip.v4.s_addr = arpei.ar_sip;
/*
 *	We've received a response.  Try to match up the packet by IP address
 *
 *	We should really start searching at the host before the cursor, as we
 *	know that the host to match cannot be the one at the cursor position
 *	because we call advance_cursor() after sending each packet.  However,
 *	the time saved is minimal, and it's not worth the extra complexity.
 */
   temp_cursor=find_host(cursor, &source_ip, packet_in, n);
   if (temp_cursor) {
/*
 *	We found an IP match for the packet. 
 */
      if (verbose > 1)
         warn_msg("---\tReceived packet #%u from %s",temp_cursor->num_recv ,my_ntoa(source_ip));
/*
 *	Display the packet and increment the number of responders if 
 *	the entry is "live" or we are not ignoring duplicates.
 */
      temp_cursor->num_recv++;
      if ((temp_cursor->live || !ignore_dups)) {
         display_packet(n, packet_in, temp_cursor, &source_ip);
         responders++;
      }
      if (verbose > 1)
         warn_msg("---\tRemoving host entry %u (%s) - Received %d bytes", temp_cursor->n, my_ntoa(source_ip), n);
      remove_host(&temp_cursor);
   } else {
/*
 *	The received packet is not from an IP address in the list
 *	Issue a message to that effect and ignore the packet.
 */
      if (verbose)
         warn_msg("---\tIgnoring %d bytes from unknown host %s", n, my_ntoa(source_ip));
   }
}

/*
 *	local_process_options	--	Process options and arguments.
 *
 *	Inputs:
 *
 *	argc	Command line arg count
 *	argv	Command line args
 *
 *	Returns:
 *
 *      0 (Zero) if this function doesn't need to do anything, or
 *      1 (One) if this function replaces the generic process_options function.
 *
 *      This protocol-specific process_options routine can replace the generic
 *      ether-scan process_options routine if required.  If it is to replace the
 *      generic routine, then it must perform all of the process_options
 *	functions and return 1.  Otherwise, it must do nothing and return 0.
 */
int
local_process_options(int argc, char *argv[]) {
   struct option long_options[] = {
      {"file", required_argument, 0, 'f'},
      {"help", no_argument, 0, 'h'},
      {"retry", required_argument, 0, 'r'},
      {"timeout", required_argument, 0, 't'},
      {"interval", required_argument, 0, 'i'},
      {"backoff", required_argument, 0, 'b'},
      {"verbose", no_argument, 0, 'v'},
      {"version", no_argument, 0, 'V'},
      {"debug", no_argument, 0, 'd'},
      {"snap", required_argument, 0, 'n'},
      {"interface", required_argument, 0, 'I'},
      {"quiet", no_argument, 0, 'q'},
      {"ignoredups", no_argument, 0, 'g'},
      {"random", no_argument, 0, 'R'},
      {"numeric", no_argument, 0, 'N'},
      {"ipv6", no_argument, 0, '6'},
      {"bandwidth", required_argument, 0, 'B'},
      {"ouifile", required_argument, 0, 'O'},
      {"arpspa", required_argument, 0, 's'},
      {"arpop", required_argument, 0, 'o'},
      {"arphrd", required_argument, 0, 'H'},
      {"arppro", required_argument, 0, 'p'},
      {"destaddr", required_argument, 0, 'T'},
      {"arppln", required_argument, 0, 'P'},
      {"arphln", required_argument, 0, 'a'},
      {"padding", required_argument, 0, 'A'},
      {"prototype", required_argument, 0, 'y'},
      {"arpsha", required_argument, 0, 'u'},
      {"arptha", required_argument, 0, 'w'},
      {0, 0, 0, 0}
   };
   const char *short_options =
      "f:hr:t:i:b:vVdn:I:qgRN6B:O:s:o:H:p:T:P:a:A:y:u:w:";
   int arg;
   int options_index=0;

   while ((arg=getopt_long_only(argc, argv, short_options, long_options, &options_index)) != -1) {
      switch (arg) {
         char interval_str[MAXLINE];    /* --interval argument */
         size_t interval_len;   /* --interval argument length */
         char bandwidth_str[MAXLINE];   /* --bandwidth argument */
         size_t bandwidth_len;  /* --bandwidth argument length */
         struct in_addr source_ip_address;
         unsigned mac_b0, mac_b1, mac_b2, mac_b3, mac_b4, mac_b5;
         int result;

         case 'f':	/* --file */
            strncpy(filename, optarg, MAXLINE);
            filename_flag=1;
            break;
         case 'h':	/* --help */
            usage(EXIT_SUCCESS);
            break;
         case 'r':	/* --retry */
            retry=Strtoul(optarg, 10);
            break;
         case 't':	/* --timeout */
            timeout=Strtoul(optarg, 10);
            break;
         case 'i':	/* --interval */
            strncpy(interval_str, optarg, MAXLINE);
            interval_len=strlen(interval_str);
            if (interval_str[interval_len-1] == 'u') {
               interval=Strtoul(interval_str, 10);
            } else {
               interval=1000 * Strtoul(interval_str, 10);
            }
            break;
         case 'b':	/* --backoff */
            backoff_factor=atof(optarg);
            break;
         case 'v':	/* --verbose */
            verbose++;
            break;
         case 'V':	/* --version */
            ether_scan_version();
            exit(0);
            break;
         case 'd':	/* --debug */
            debug++;
            break;
         case 'n':	/* --snap */
            snaplen=strtol(optarg, (char **)NULL, 0);
            break;
         case 'I':	/* --interface */
            if_name = make_message("%s", optarg);
            break;
         case 'q':	/* --quiet */
            quiet_flag=1;
            break;
         case 'g':	/* --ignoredups */
            ignore_dups=1;
            break;
         case 'R':	/* --random */
            random_flag=1;
            break;
         case 'N':	/* --numeric */
            numeric_flag=1;
            break;
         case '6':	/* --ipv6 */
            ipv6_flag=1;
            break;
         case 'B':      /* --bandwidth */
            strncpy(bandwidth_str, optarg, MAXLINE);
            bandwidth_len=strlen(bandwidth_str);
            if (bandwidth_str[bandwidth_len-1] == 'M') {
               bandwidth=1000000 * Strtoul(bandwidth_str, 10);
            } else if (bandwidth_str[bandwidth_len-1] == 'K') {
               bandwidth=1000 * Strtoul(bandwidth_str, 10);
            } else {
               bandwidth=Strtoul(bandwidth_str, 10);
            }
            break;
         case 'O':	/* --ouifile */
            strncpy(ouifilename, optarg, MAXLINE);
            break;
         case 's':	/* --arpspa */
            arp_spa_flag = 1;
            if ((inet_pton(AF_INET, optarg, &source_ip_address)) <= 0)
               err_sys("inet_pton failed for %s", optarg);
            memcpy(&arp_spa, &(source_ip_address.s_addr), sizeof(arp_spa));
            break;
         case 'o':	/* --arpop */
            arp_op=strtol(optarg, (char **)NULL, 0);
            break;
         case 'H':	/* --arphrd */
            arp_hrd=strtol(optarg, (char **)NULL, 0);
            break;
         case 'p':	/* --arppro */
            arp_pro=strtol(optarg, (char **)NULL, 0);
            break;
         case 'T':	/* --destaddr */
            result = sscanf(optarg, "%x:%x:%x:%x:%x:%x", &mac_b0,
                            &mac_b1, &mac_b2, &mac_b3, &mac_b4, &mac_b5);
            if (result !=6 )
               err_msg("Invalid target MAC address: %s", optarg);
            target_mac[0] = mac_b0;
            target_mac[1] = mac_b1;
            target_mac[2] = mac_b2;
            target_mac[3] = mac_b3;
            target_mac[4] = mac_b4;
            target_mac[5] = mac_b5;
            break;
         case 'P':	/* --arppln */
            arp_pln=strtol(optarg, (char **)NULL, 0);
            break;
         case 'a':	/* --arphln */
            arp_hln=strtol(optarg, (char **)NULL, 0);
            break;
         case 'A':	/* --padding */
            if (strlen(optarg) % 2)     /* Length is odd */
               err_msg("ERROR: Length of --padding argument must be even (multiple of 2).");
            padding=hex2data(optarg, &padding_len);
            break;
         case 'y':	/* --prototype */
            eth_pro=strtol(optarg, (char **)NULL, 0);
            break;
         case 'u':	/* --arpsha */
            result = sscanf(optarg, "%x:%x:%x:%x:%x:%x", &mac_b0,
                            &mac_b1, &mac_b2, &mac_b3, &mac_b4, &mac_b5);
            if (result !=6 )
               err_msg("Invalid source MAC address: %s", optarg);
            arp_sha[0] = mac_b0;
            arp_sha[1] = mac_b1;
            arp_sha[2] = mac_b2;
            arp_sha[3] = mac_b3;
            arp_sha[4] = mac_b4;
            arp_sha[5] = mac_b5;
            arp_sha_flag = 1;
            break;
         case 'w':	/* --arptha */
            result = sscanf(optarg, "%x:%x:%x:%x:%x:%x", &mac_b0,
                            &mac_b1, &mac_b2, &mac_b3, &mac_b4, &mac_b5);
            if (result !=6 )
               err_msg("Invalid target MAC address: %s", optarg);
            arp_tha[0] = mac_b0;
            arp_tha[1] = mac_b1;
            arp_tha[2] = mac_b2;
            arp_tha[3] = mac_b3;
            arp_tha[4] = mac_b4;
            arp_tha[5] = mac_b5;
            break;
         default:	/* Unknown option */
            usage(EXIT_FAILURE);
            break;
      }
   }
   return 1;	/* Replace generic process_options() function */
}

/*
 *	marshal_arp_pkt -- Marshal ARP packet from struct to buffer
 *
 *	Inputs:
 *
 *	buffer		Pointer to the output buffer
 *	arp_pkt		The ARP packet
 *	buf_siz		The size of the output buffer
 *
 *	Returns:
 *
 *	None
 */
void
marshal_arp_pkt(unsigned char *buffer, arp_ether_ipv4 *arp_pkt,
                size_t *buf_siz) {
   unsigned char *cp;

   *buf_siz = sizeof(arp_pkt->ar_hrd) + sizeof(arp_pkt->ar_pro) +
              sizeof(arp_pkt->ar_hln) + sizeof(arp_pkt->ar_pln) +
              sizeof(arp_pkt->ar_op)  + sizeof(arp_pkt->ar_sha) +
              sizeof(arp_pkt->ar_sip) + sizeof(arp_pkt->ar_tha) +
              sizeof(arp_pkt->ar_tip);
   cp = buffer;

   memcpy(cp, &(arp_pkt->ar_hrd), sizeof(arp_pkt->ar_hrd));
   cp += sizeof(arp_pkt->ar_hrd);
   memcpy(cp, &(arp_pkt->ar_pro), sizeof(arp_pkt->ar_pro));
   cp += sizeof(arp_pkt->ar_pro);
   memcpy(cp, &(arp_pkt->ar_hln), sizeof(arp_pkt->ar_hln));
   cp += sizeof(arp_pkt->ar_hln);
   memcpy(cp, &(arp_pkt->ar_pln), sizeof(arp_pkt->ar_pln));
   cp += sizeof(arp_pkt->ar_pln);
   memcpy(cp, &(arp_pkt->ar_op), sizeof(arp_pkt->ar_op));
   cp += sizeof(arp_pkt->ar_op);
   memcpy(cp, &(arp_pkt->ar_sha), sizeof(arp_pkt->ar_sha));
   cp += sizeof(arp_pkt->ar_sha);
   memcpy(cp, &(arp_pkt->ar_sip), sizeof(arp_pkt->ar_sip));
   cp += sizeof(arp_pkt->ar_sip);
   memcpy(cp, &(arp_pkt->ar_tha), sizeof(arp_pkt->ar_tha));
   cp += sizeof(arp_pkt->ar_tha);
   memcpy(cp, &(arp_pkt->ar_tip), sizeof(arp_pkt->ar_tip));
}

/*
 *	unmarshal_arp_pkt -- Un Marshal ARP packet from buffer to struct
 *
 *	Inputs:
 *
 *	buffer		Pointer to the input buffer
 *	arp_pkt		The output struct
 *
 *	Returns:
 *
 *	None
 */
void
unmarshal_arp_pkt(const unsigned char *buffer, arp_ether_ipv4 *arp_pkt) {
   const unsigned char *cp;

   cp = buffer;

   memcpy(&(arp_pkt->ar_hrd), cp, sizeof(arp_pkt->ar_hrd));
   cp += sizeof(arp_pkt->ar_hrd);
   memcpy(&(arp_pkt->ar_pro), cp, sizeof(arp_pkt->ar_pro));
   cp += sizeof(arp_pkt->ar_pro);
   memcpy(&(arp_pkt->ar_hln), cp, sizeof(arp_pkt->ar_hln));
   cp += sizeof(arp_pkt->ar_hln);
   memcpy(&(arp_pkt->ar_pln), cp, sizeof(arp_pkt->ar_pln));
   cp += sizeof(arp_pkt->ar_pln);
   memcpy(&(arp_pkt->ar_op), cp, sizeof(arp_pkt->ar_op));
   cp += sizeof(arp_pkt->ar_op);
   memcpy(&(arp_pkt->ar_sha), cp, sizeof(arp_pkt->ar_sha));
   cp += sizeof(arp_pkt->ar_sha);
   memcpy(&(arp_pkt->ar_sip), cp, sizeof(arp_pkt->ar_sip));
   cp += sizeof(arp_pkt->ar_sip);
   memcpy(&(arp_pkt->ar_tha), cp, sizeof(arp_pkt->ar_tha));
   cp += sizeof(arp_pkt->ar_tha);
   memcpy(&(arp_pkt->ar_tip), cp, sizeof(arp_pkt->ar_tip));
}

/*
 *      hex2data -- Convert hex string to binary data
 *
 *      Inputs:
 *
 *      string          The string to convert
 *      data_len        (output) The length of the resultant binary data
 *
 *      Returns:
 *
 *      Pointer to the binary data.
 *
 *      The returned pointer points to malloc'ed storage which should be
 *      free'ed by the caller when it's no longer needed.  If the length of
 *      the inputs string is not even, the function will return NULL and
 *      set data_len to 0.
 */
unsigned char *
hex2data(const char *string, size_t *data_len) {
   unsigned char *data;
   unsigned char *cp;
   unsigned i;
   size_t len;

   if (strlen(string) %2 ) {    /* Length is odd */
      *data_len = 0;
      return NULL;
   }

   len = strlen(string) / 2;
   data = Malloc(len);
   cp = data;
   for (i=0; i<len; i++)
      *cp++=hstr_i(&string[i*2]);
   *data_len = len;
   return data;
}

/*
 *      hstr_i -- Convert two-digit hex string to unsigned integer
 *
 *      Inputs:
 *
 *      cptr    Two-digit hex string
 *
 *      Returns:
 *
 *      Number corresponding to input hex value.
 *
 *      An input of "0A" or "0a" would return 10.
 *      Note that this function does no sanity checking, it's up to the
 *      caller to ensure that *cptr points to at least two hex digits.
 *
 *      This function is a modified version of hstr_i at www.snippets.org.
 */
unsigned int
hstr_i(const char *cptr)
{
      unsigned int i;
      unsigned int j = 0;
      int k;

      for (k=0; k<2; k++) {
            i = *cptr++ - '0';
            if (9 < i)
                  i -= 7;
            j <<= 4;
            j |= (i & 0x0f);
      }
      return j;
}
/*
 *      hexstring -- Convert data to printable hex string form
 *
 *      Inputs:
 *
 *      string  Pointer to input data.
 *      size    Size of input data.
 *
 *      Returns:
 *
 *      Pointer to the printable hex string.
 *
 *      Each byte in the input data will be represented by two hex digits
 *      in the output string.  Therefore the output string will be twice
 *      as long as the input data plus one extra byte for the trailing NULL.
 *
 *      The pointer returned points to malloc'ed storage which should be
 *      free'ed by the caller when it's no longer needed.
 */
char *
hexstring(const unsigned char *data, size_t size) {
   char *result;
   char *r;
   const unsigned char *cp;
   unsigned i;
/*
 *      If the input data is NULL, return an empty string.
 */
   if (data == NULL) {
      result = Malloc(1);
      result[0] = '\0';
      return result;
   }
/*
 *      Create and return hex string.
 */
   result = Malloc(2*size + 1);
   cp = data;
   r = result;
   for (i=0; i<size; i++) {
      sprintf(r, "%.2x", *cp++);
      r += 2;
   }
   *r = '\0';

   return result;
}

