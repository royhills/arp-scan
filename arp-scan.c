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

#include "arp-scan.h"

static char const rcsid[] = "$Id: arp-scan.c 7543 2006-06-07 06:28:04Z rsh $";   /* RCS ID for ident(1) */

/* Global variables */
host_entry *helist = NULL;              /* Array of host entries */
host_entry **helistptr;                 /* Array of pointers to host entries */
host_entry **cursor;                    /* Pointer to current host entry ptr */
unsigned num_hosts = 0;                 /* Number of entries in the list */
unsigned responders = 0;                /* Number of hosts which responded */
unsigned live_count;                    /* Number of entries awaiting reply */
unsigned max_iter;                      /* Max iterations in find_host() */
int verbose=0;                          /* Verbose level */
int debug = 0;                          /* Debug flag */
pcap_t *handle;                         /* pcap handle */
int pcap_fd;                            /* Pcap file descriptor */
char filename[MAXLINE];
int filename_flag=0;
int random_flag=0;                      /* Randomise the list */
int numeric_flag=0;                     /* IP addresses only */
int ipv6_flag=0;                        /* IPv6 */
int ether_flag=0;                       /* Ethernet addresses */
unsigned interval=0;                    /* Desired interval between packets */
unsigned bandwidth=DEFAULT_BANDWIDTH;   /* Bandwidth in bits per sec */

unsigned retry = DEFAULT_RETRY;		/* Number of retries */
unsigned timeout = DEFAULT_TIMEOUT;	/* Per-host timeout */
float backoff_factor = DEFAULT_BACKOFF_FACTOR;	/* Backoff factor */
int snaplen = SNAPLEN;			/* Pcap snap length */
char *if_name=NULL;			/* Interface name, e.g. "eth0" */
int quiet_flag=0;			/* Don't decode the packet */
int ignore_dups=0;			/* Don't display duplicate packets */

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

int
main(int argc, char *argv[]) {
   char arg_str[MAXLINE];       /* Args as string for syslog */
   int sockfd;                  /* IP socket file descriptor */
   struct sockaddr_in sa_peer;
   struct timeval now;
   unsigned char packet_in[MAXIP];      /* Received packet */
   struct timeval diff;         /* Difference between two timevals */
   int select_timeout;          /* Select timeout */
   ARP_UINT64 loop_timediff;    /* Time since last packet sent in us */
   ARP_UINT64 host_timediff; /* Time since last pkt sent to this host (us) */
   int arg;
   int arg_str_space;           /* Used to avoid buffer overruns when copying */
   struct timeval last_packet_time;     /* Time last packet was sent */
   int req_interval;            /* Requested per-packet interval */
   int cum_err=0;               /* Cumulative timing error */
   struct timeval start_time;   /* Program start time */
   struct timeval end_time;     /* Program end time */
   struct timeval elapsed_time; /* Elapsed time as timeval */
   double elapsed_seconds;      /* Elapsed time in seconds */
   static int reset_cum_err;
   static int pass_no;
   int first_timeout=1;
   int i;
/*
 *      Open syslog channel and log arguments if required.
 *      We must be careful here to avoid overflowing the arg_str buffer
 *      which could result in a buffer overflow vulnerability.  That's why
 *      we use strncat and keep track of the remaining buffer space.
 */
#ifdef SYSLOG
   openlog("arp-scan", LOG_PID, SYSLOG_FACILITY);
   arg_str[0] = '\0';
   arg_str_space = MAXLINE;     /* Amount of space in the arg_str buffer */
   for (arg=0; arg<argc; arg++) {
      arg_str_space -= strlen(argv[arg]);
      if (arg_str_space > 0) {
         strncat(arg_str, argv[arg], (size_t) arg_str_space);
         if (arg < (argc-1)) {
            strcat(arg_str, " ");
            arg_str_space--;
         }
      }
   }
   info_syslog("Starting: %s", arg_str);
#endif
/*
 *      Process options.
 */
   process_options(argc, argv);
/*
 *      Get program start time for statistics displayed on completion.
 */
   Gettimeofday(&start_time);
   if (debug) {print_times(); printf("main: Start\n");}
/*
 *      Create packet socket.  This socket is used to send outbound packets.
 */
   if ((sockfd = socket(PF_PACKET, SOCK_DGRAM, 0)) < 0)
      err_sys("socket");
/*
 *      Call protocol-specific initialisation routine to perform any
 *      initial setup required.
 */
   initialise();
/*
 *      Drop privileges.
 */
   if ((setuid(getuid())) < 0) {
      err_sys("setuid");
   }
/*
 *      If we're not reading from a file, then we must have some hosts
 *      given as command line arguments.
 */
   if (!filename_flag)
      if ((argc - optind) < 1)
         usage(EXIT_FAILURE);
/*
 *      Populate the list from the specified file if --file was specified, or
 *      otherwise from the remaining command line arguments.
 */
   if (filename_flag) { /* Populate list from file */
      FILE *fp;
      char line[MAXLINE];
      char *cp;

      if ((strcmp(filename, "-")) == 0) {       /* Filename "-" means stdin */
         if ((fp = fdopen(0, "r")) == NULL) {
            err_sys("fdopen");
         }
      } else {
         if ((fp = fopen(filename, "r")) == NULL) {
            err_sys("fopen");
         }
      }

      while (fgets(line, MAXLINE, fp)) {
         cp = line;
         while (!isspace(*cp) && *cp != '\0')
            cp++;
         *cp = '\0';
         add_host_pattern(line, timeout);
      }
      fclose(fp);
   } else {             /* Populate list from command line arguments */
      argv=&argv[optind];
      while (*argv) {
         add_host_pattern(*argv, timeout);
         argv++;
      }
   }
/*
 *      Check that we have at least one entry in the list.
 */
   if (!num_hosts)
      err_msg("No hosts to process.");
/*
 *      Check that the combination of specified options and arguments is
 *      valid.
 */
   if (interval && bandwidth != DEFAULT_BANDWIDTH)
      err_msg("ERROR: You cannot specify both --bandwidth and --interval.");
/*
 *      Create and initialise array of pointers to host entries.
 */
   helistptr = Malloc(num_hosts * sizeof(host_entry *));
   for (i=0; i<num_hosts; i++)
      helistptr[i] = &helist[i];
/*
 *      Randomise the list if required.
 */
   if (random_flag) {
      unsigned seed;
      struct timeval tv;
      int r;
      host_entry *temp;

      Gettimeofday(&tv);
      seed = tv.tv_usec ^ getpid();
      srandom(seed);

      for (i=num_hosts-1; i>0; i--) {
         r = random() % (i+1);     /* Random number 0<=r<i */
         temp = helistptr[i];
         helistptr[i] = helistptr[r];
         helistptr[r] = temp;
      }
   }
/*
 *      Set current host pointer (cursor) to start of list, zero
 *      last packet sent time, and set last receive time to now.
 */
   live_count = num_hosts;
   cursor = helistptr;
   last_packet_time.tv_sec=0;
   last_packet_time.tv_usec=0;
/*
 *      Calculate the required interval to achieve the required outgoing
 *      bandwidth unless the interval was manually specified with --interval.
 */
   if (!interval) {
      size_t packet_out_len;

      packet_out_len=send_packet(0, NULL, NULL); /* Get packet data size */
      if (packet_out_len < MINIMUM_FRAME_SIZE)
         packet_out_len = MINIMUM_FRAME_SIZE;   /* Adjust to minimum size */
      packet_out_len += PACKET_OVERHEAD;        /* Add layer 2 overhead */
      interval = ((ARP_UINT64)packet_out_len * 8 * 1000000) / bandwidth;
      if (verbose) {
         warn_msg("DEBUG: pkt len=%u bytes, bandwidth=%u bps, interval=%u us",
                  packet_out_len, bandwidth, interval);
      }
   }
/*
 *      Display initial message.
 */
   printf("Starting %s with %u hosts (http://www.nta-monitor.com/arp-scan/)\n",
          PACKAGE_STRING, num_hosts);
/*
 *      Display the lists if verbose setting is 3 or more.
 */
   if (verbose > 2)
      dump_list();
/*
 *      Main loop: send packets to all hosts in order until a response
 *      has been received or the host has exhausted its retry limit.
 *
 *      The loop exits when all hosts have either responded or timed out.
 */
   reset_cum_err = 1;
   req_interval = interval;
   while (live_count) {
      if (debug) {print_times(); printf("main: Top of loop.\n");}
/*
 *      Obtain current time and calculate deltas since last packet and
 *      last packet to this host.
 */
      Gettimeofday(&now);
/*
 *      If the last packet was sent more than interval us ago, then we can
 *      potentially send a packet to the current host.
 */
      timeval_diff(&now, &last_packet_time, &diff);
      loop_timediff = (ARP_UINT64)1000000*diff.tv_sec + diff.tv_usec;
      if (loop_timediff >= req_interval) {
         if (debug) {print_times(); printf("main: Can send packet now.  loop_timediff=" ARP_UINT64_FORMAT "\n", loop_timediff);}
/*
 *      If the last packet to this host was sent more than the current
 *      timeout for this host us ago, then we can potentially send a packet
 *      to it.
 */
         timeval_diff(&now, &((*cursor)->last_send_time), &diff);
         host_timediff = (ARP_UINT64)1000000*diff.tv_sec + diff.tv_usec;
         if (host_timediff >= (*cursor)->timeout) {
            if (reset_cum_err) {
               if (debug) {print_times(); printf("main: Reset cum_err\n");}
               cum_err = 0;
               req_interval = interval;
               reset_cum_err = 0;
            } else {
               cum_err += loop_timediff - interval;
               if (req_interval >= cum_err) {
                  req_interval = req_interval - cum_err;
               } else {
                  req_interval = 0;
               }
            }
            if (debug) {print_times(); printf("main: Can send packet to host %d now.  host_timediff=" ARP_UINT64_FORMAT ", timeout=%u, req_interval=%d, cum_err=%d\n", (*cursor)->n, host_timediff, (*cursor)->timeout, req_interval, cum_err);}
            select_timeout = req_interval;
/*
 *      If we've exceeded our retry limit, then this host has timed out so
 *      remove it from the list.  Otherwise, increase the timeout by the
 *      backoff factor if this is not the first packet sent to this host
 *      and send a packet.
 */
            if (verbose && (*cursor)->num_sent > pass_no) {
               warn_msg("---\tPass %d complete", pass_no+1);
               pass_no = (*cursor)->num_sent;
            }
            if ((*cursor)->num_sent >= retry) {
               if (verbose > 1)
                  warn_msg("---\tRemoving host entry %u (%s) - Timeout", (*cursor)->n, my_ntoa((*cursor)->addr));
               if (debug) {print_times(); printf("main: Timing out host %d.\n", (*cursor)->n);}
               remove_host(cursor);     /* Automatically calls advance_cursor() */
               if (first_timeout) {
                  timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                  host_timediff = (ARP_UINT64)1000000*diff.tv_sec +
                                  diff.tv_usec;
                  while (host_timediff >= (*cursor)->timeout && live_count) {
                     if ((*cursor)->live) {
                        if (verbose > 1)
                           warn_msg("---\tRemoving host %u (%s) - Catch-Up Timeout", (*cursor)->n, my_ntoa((*cursor)->addr));
                        remove_host(cursor);
                     } else {
                        advance_cursor();
                     }
                     timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                     host_timediff = (ARP_UINT64)1000000*diff.tv_sec +
                                     diff.tv_usec;
                  }
                  first_timeout=0;
               }
               Gettimeofday(&last_packet_time);
            } else {    /* Retry limit not reached for this host */
               if ((*cursor)->num_sent)
                  (*cursor)->timeout *= backoff_factor;
               send_packet(sockfd, *cursor, &last_packet_time);
               advance_cursor();
            }
         } else {       /* We can't send a packet to this host yet */
/*
 *      Note that there is no point calling advance_cursor() here because if
 *      host n is not ready to send, then host n+1 will not be ready either.
 */
            select_timeout = (*cursor)->timeout - host_timediff;
            reset_cum_err = 1;  /* Zero cumulative error */
            if (debug) {print_times(); printf("main: Can't send packet to host %d yet. host_timediff=" ARP_UINT64_FORMAT "\n", (*cursor)->n, host_timediff);}
         } /* End If */
      } else {          /* We can't send a packet yet */
         select_timeout = req_interval - loop_timediff;
         if (debug) {print_times(); printf("main: Can't send packet yet.  loop_timediff=" ARP_UINT64_FORMAT "\n", loop_timediff);}
      } /* End If */

      recvfrom_wto(pcap_fd, packet_in, MAXIP, (struct sockaddr *)&sa_peer,
                   select_timeout);
   } /* End While */

   printf("\n");        /* Ensure we have a blank line */

   close(sockfd);
   clean_up();

   Gettimeofday(&end_time);
   timeval_diff(&end_time, &start_time, &elapsed_time);
   elapsed_seconds = (elapsed_time.tv_sec*1000 +
                      elapsed_time.tv_usec/1000) / 1000.0;

#ifdef SYSLOG
   info_syslog("Ending: %u hosts scanned in %.3f seconds (%.2f hosts/sec). %u responded",
               num_hosts, elapsed_seconds, num_hosts/elapsed_seconds,
               responders);
#endif
   printf("Ending %s: %u hosts scanned in %.3f seconds (%.2f hosts/sec).  %u responded\n",
          PACKAGE_STRING, num_hosts, elapsed_seconds,
          num_hosts/elapsed_seconds, responders);
   if (debug) {print_times(); printf("main: End\n");}
   return 0;
}

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
 *	usage -- display usage message and exit
 *
 *	Inputs:
 *
 *	status	Status to pass to exit()
 */
void
usage(int status) {
   fprintf(stderr, "Usage: arp-scan [options] [hosts...]\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Target hosts must be specified on the command line unless the --file option is\n");
   fprintf(stderr, "given, in which case the targets are read from the specified file instead.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "The target hosts can be specified as IP addresses or hostnames.  You can also\n");
   fprintf(stderr, "specify the target as IPnetwork/bits (e.g. 192.168.1.0/24) to specify all hosts\n");
   fprintf(stderr, "in the given network (network and broadcast addresses included), or\n");
   fprintf(stderr, "IPstart-IPend (e.g. 192.168.1.3-192.168.1.27) to specify all hosts in the\n");
   fprintf(stderr, "inclusive range.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "These different options for specifying target hosts may be used both on the\n");
   fprintf(stderr, "command line, and also in the file specified with the --file option.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Options:\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "--help or -h\t\tDisplay this usage message and exit.\n");
   fprintf(stderr, "\n--file=<fn> or -f <fn>\tRead hostnames or addresses from the specified file\n");
   fprintf(stderr, "\t\t\tinstead of from the command line. One name or IP\n");
   fprintf(stderr, "\t\t\taddress per line.  Use \"-\" for standard input.\n");
   fprintf(stderr, "\n--retry=<n> or -r <n>\tSet total number of attempts per host to <n>,\n");
   fprintf(stderr, "\t\t\tdefault=%d.\n", retry);
   fprintf(stderr, "\n--timeout=<n> or -t <n>\tSet initial per host timeout to <n> ms, default=%d.\n", timeout);
   fprintf(stderr, "\t\t\tThis timeout is for the first packet sent to each host.\n");
   fprintf(stderr, "\t\t\tsubsequent timeouts are multiplied by the backoff\n");
   fprintf(stderr, "\t\t\tfactor which is set with --backoff.\n");
   fprintf(stderr, "\n--interval=<n> or -i <n> Set minimum packet interval to <n> ms, default=%d.\n", interval/1000);
   fprintf(stderr, "\t\t\tThis controls the outgoing bandwidth usage by limiting\n");
   fprintf(stderr, "\t\t\tthe rate at which packets can be sent.  The packet\n");
   fprintf(stderr, "\t\t\tinterval will be no smaller than this number.\n");
   fprintf(stderr, "\t\t\tIf you want to use up to a given bandwidth, then it is\n");
   fprintf(stderr, "\t\t\teasier to use the --bandwidth option instead.\n");
   fprintf(stderr, "\t\t\tThe interval specified is in milliseconds by default,\n");
   fprintf(stderr, "\t\t\tor in microseconds if \"u\" is appended to the value.\n");
   fprintf(stderr, "\n--bandwidth=<n> or -B <n> Set desired outbound bandwidth to <n>.\n");
   fprintf(stderr, "\t\t\tThe value is in bits per second by default.  If you\n");
   fprintf(stderr, "\t\t\tappend \"K\" to the value, then the units are kilobits\n");
   fprintf(stderr, "\t\t\tper sec; and if you append \"M\" to the value, the\n");
   fprintf(stderr, "\t\t\tunits are megabits per second.\n");
   fprintf(stderr, "\t\t\tThe \"K\" and \"M\" suffixes represent the decimal, not\n");
   fprintf(stderr, "\t\t\tbinary, multiples.  So 64K is 64000, not 65536.\n");
   fprintf(stderr, "\t\t\tYou cannot specify both --interval and --bandwidth\n");
   fprintf(stderr, "\t\t\tbecause they are just different ways to change the\n");
   fprintf(stderr, "\t\t\tsame parameter.\n");
   fprintf(stderr, "\n--backoff=<b> or -b <b>\tSet timeout backoff factor to <b>, default=%.2f.\n", backoff_factor);
   fprintf(stderr, "\t\t\tThe per-host timeout is multiplied by this factor\n");
   fprintf(stderr, "\t\t\tafter each timeout.  So, if the number of retrys\n");
   fprintf(stderr, "\t\t\tis 3, the initial per-host timeout is 500ms and the\n");
   fprintf(stderr, "\t\t\tbackoff factor is 1.5, then the first timeout will be\n");
   fprintf(stderr, "\t\t\t500ms, the second 750ms and the third 1125ms.\n");
   fprintf(stderr, "\n--verbose or -v\t\tDisplay verbose progress messages.\n");
   fprintf(stderr, "\t\t\tUse more than once for greater effect:\n");
   fprintf(stderr, "\t\t\t1 - Show when hosts are removed from the list and\n");
   fprintf(stderr, "\t\t\t    other useful information.\n");
   fprintf(stderr, "\t\t\t2 - Show each packet sent and received.\n");
   fprintf(stderr, "\t\t\t3 - Display the host list before scanning starts.\n");
   fprintf(stderr, "\n--version or -V\t\tDisplay program version and exit.\n");
   fprintf(stderr, "\n--random or -R\t\tRandomise the host list.\n");
   fprintf(stderr, "\t\t\tThis option randomises the order of the hosts in the\n");
   fprintf(stderr, "\t\t\thost list, so the ARP packets are sent to the hosts in\n");
   fprintf(stderr, "\t\t\ta random order.  It uses the Knuth shuffle algorithm.\n");
   fprintf(stderr, "\n--numeric or -N\t\tIP addresses only, no hostnames.\n");
   fprintf(stderr, "\t\t\tWith this option, all hosts must be specified as\n");
   fprintf(stderr, "\t\t\tIP addresses.  Hostnames are not permitted.\n");
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
   fprintf(stderr, "\n");
   fprintf(stderr, "Report bugs or send suggestions to %s\n", PACKAGE_BUGREPORT);
   exit(status);
}

/*
 *	print_times -- display timing details for debugging.
 *
 *	Inputs:
 *
 *	None.
 */
void
print_times(void) {
   static struct timeval time_first;	/* When print_times() was first called */
   static struct timeval time_last;	/* When print_times() was last called */
   static int first_call=1;
   struct timeval time_now;
   struct timeval time_delta1;
   struct timeval time_delta2;

   Gettimeofday(&time_now);
   
   if (first_call) {
      first_call=0;
      time_first.tv_sec  = time_now.tv_sec;
      time_first.tv_usec = time_now.tv_usec;
      printf("%lu.%.6lu (0.000000) [0.000000]\t", time_now.tv_sec,
             time_now.tv_usec);
   } else {
      timeval_diff(&time_now, &time_last, &time_delta1);
      timeval_diff(&time_now, &time_first, &time_delta2);
      printf("%lu.%.6lu (%lu.%.6lu) [%lu.%.6lu]\t", time_now.tv_sec,
             time_now.tv_usec, time_delta1.tv_sec, time_delta1.tv_usec,
             time_delta2.tv_sec, time_delta2.tv_usec);
   }
   time_last.tv_sec  = time_now.tv_sec;
   time_last.tv_usec = time_now.tv_usec;
}

/*
 * make_message -- allocate a sufficiently large string and print into it.
 *
 * Inputs:
 *
 * Format and variable number of arguments.
 *
 * Outputs:
 *
 * Pointer to the string,
 *
 * The code for this function is from the Debian Linux "woody" sprintf man
 * page.  Modified slightly to use wrapper functions for malloc and realloc.
 */
char *
make_message(const char *fmt, ...) {
   int n;
   /* Guess we need no more than 100 bytes. */
   size_t size = 100;
   char *p;
   va_list ap;
   p = Malloc (size);
   while (1) {
      /* Try to print in the allocated space. */
      va_start(ap, fmt);
      n = vsnprintf (p, size, fmt, ap);
      va_end(ap);
      /* If that worked, return the string. */
      if (n > -1 && n < size)
         return p;
      /* Else try again with more space. */
      if (n > -1)    /* glibc 2.1 */
         size = n+1; /* precisely what is needed */
      else           /* glibc 2.0 */
         size *= 2;  /* twice the old size */
      p = Realloc (p, size);
   }
}

/*
 *      printable -- Convert string to printable form using C-style escapes
 *
 *      Inputs:
 *
 *      string  Pointer to input string.
 *      size    Size of input string.  0 means that string is null-terminated.
 *
 *      Returns:
 *
 *      Pointer to the printable string.
 *
 *      Any non-printable characters are replaced by C-Style escapes, e.g.
 *      "\n" for newline.  As a result, the returned string may be longer than
 *      the one supplied.
 *
 *      This function makes two passes through the input string: one to
 *      determine the required output length, then a second to perform the
 *      conversion.
 *
 *      The pointer returned points to malloc'ed storage which should be
 *      free'ed by the caller when it's no longer needed.
 */
char *
printable(const unsigned char *string, size_t size) {
   char *result;
   char *r;
   const unsigned char *cp;
   size_t outlen;
   unsigned i;
/*
 *      If the input string is NULL, return an empty string.
 */
   if (string == NULL) {
      result = Malloc(1);
      result[0] = '\0';
      return result;
   }
/*
 *      Determine required size of output string.
 */
   if (!size)
      size = strlen((const char *) string);

   outlen = size;
   cp = string;
   for (i=0; i<size; i++) {
      switch (*cp) {
         case '\b':
         case '\f':
         case '\n':
         case '\r':
         case '\t':
         case '\v':
            outlen++;
            break;
         default:
            if(!isprint(*cp))
               outlen += 3;
      }
      cp++;
   }
   outlen++;    /* One more for the ending NULL */

   result = Malloc(outlen);

   cp = string;
   r = result;
   for (i=0; i<size; i++) {
      switch (*cp) {
         case '\b':
            *r++ = '\\';
            *r++ = 'b';
            break;
         case '\f':
            *r++ = '\\';
            *r++ = 'f';
            break;
         case '\n':
            *r++ = '\\';
            *r++ = 'n';
            break;
         case '\r':
            *r++ = '\\';
            *r++ = 'r';
            break;
         case '\t':
            *r++ = '\\';
            *r++ = 't';
            break;
         case '\v':
            *r++ = '\\';
            *r++ = 'v';
            break;
         default:
            if (isprint(*cp)) {
               *r++ = *cp;      /* Printable character */
            } else {
               *r++ = '\\';
               sprintf(r, "%.3o", *cp);
               r += 3;
            }
            break;
      }
      cp++;
   }
   *r = '\0';

   return result;
}

/*
 *      add_host_pattern -- Add one or more new host to the list.
 *
 *      Inputs:
 *
 *      pattern = The host pattern to add.
 *      timeout = Per-host timeout in ms.
 *
 *      Returns: None
 *
 *      This adds one or more new hosts to the list.  The pattern argument
 *      can either be a single host or IP address, in which case one host
 *      will be added to the list, or it can specify a number of hosts with
 *      the IPnet/bits or IPstart-IPend formats.
 *
 *      The timeout and num_hosts arguments are passed unchanged to add_host().
 */
void
add_host_pattern(const char *pattern, unsigned timeout) {
   char *patcopy;
   struct in_addr in_val;
   struct in_addr mask_val;
   unsigned numbits;
   char *cp;
   uint32_t ipnet_val;
   uint32_t network;
   uint32_t mask;
   unsigned long hoststart;
   unsigned long hostend;
   unsigned i;
   uint32_t x;
   static int first_call=1;
   static regex_t iprange_pat;
   static regex_t ipslash_pat;
   static regex_t ipmask_pat;
   static const char *iprange_pat_str =
      "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+-[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";
   static const char *ipslash_pat_str =
      "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+";
   static const char *ipmask_pat_str =
      "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";
/*
 *      Compile regex patterns if this is the first time we've been called.
 */
   if (first_call) {
      int result;

      first_call = 0;
      if ((result=regcomp(&iprange_pat, iprange_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         size_t errlen;
         errlen=regerror(result, &iprange_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 iprange_pat_str, errbuf);
      }
      if ((result=regcomp(&ipslash_pat, ipslash_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         size_t errlen;
         errlen=regerror(result, &ipslash_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 ipslash_pat_str, errbuf);
      }
      if ((result=regcomp(&ipmask_pat, ipmask_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         size_t errlen;
         errlen=regerror(result, &ipmask_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 ipmask_pat_str, errbuf);
      }
   }
/*
 *      Make a copy of pattern because we don't want to modify our argument.
 */
   patcopy=Malloc(strlen(pattern)+1);
   strcpy(patcopy, pattern);

   if (!(regexec(&ipslash_pat, patcopy, 0, NULL, 0))) { /* IPnet/bits */
/*
 *      Get IPnet and bits as integers.  Perform basic error checking.
 */
      cp=strchr(patcopy, '/');
      *(cp++)='\0';     /* patcopy points to IPnet, cp points to bits */
      if (!(inet_aton(patcopy, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", patcopy);
      ipnet_val=ntohl(in_val.s_addr);   /* We need host byte order */
      numbits=Strtoul(cp, 10);
      if (numbits<3 || numbits>32)
         err_msg("ERROR: Number of bits in %s must be between 3 and 32",
                 pattern);
/*
 *      Construct 32-bit network bitmask from number of bits.
 */
      mask=0;
      for (i=0; i<numbits; i++)
         mask += 1 << i;
      mask = mask << (32-i);
/*
 *      Mask off the network.  Warn if the host bits were non-zero.
 */
      network=ipnet_val & mask;
      if (network != ipnet_val)
         warn_msg("WARNING: host part of %s is non-zero", pattern);
/*
 *      Determine maximum and minimum host values.  We include the host
 *      and broadcast.
 */
      hoststart=0;
      hostend=(1<<(32-numbits))-1;
/*
 *      Calculate all host addresses in the range and feed to add_host()
 *      in dotted-quad format.
 */
      for (i=hoststart; i<=hostend; i++) {
         uint32_t hostip;
         int b1, b2, b3, b4;
         char ipstr[16];

         hostip = network+i;
         b1 = (hostip & 0xff000000) >> 24;
         b2 = (hostip & 0x00ff0000) >> 16;
         b3 = (hostip & 0x0000ff00) >> 8;
         b4 = (hostip & 0x000000ff);
         sprintf(ipstr, "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, timeout);
      }
   } else if (!(regexec(&ipmask_pat, patcopy, 0, NULL, 0))) { /* IPnet:netmask */
/*
 *      Get IPnet and bits as integers.  Perform basic error checking.
 */
      cp=strchr(patcopy, ':');
      *(cp++)='\0';     /* patcopy points to IPnet, cp points to netmask */
      if (!(inet_aton(patcopy, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", patcopy);
      ipnet_val=ntohl(in_val.s_addr);   /* We need host byte order */
      if (!(inet_aton(cp, &mask_val)))
         err_msg("ERROR: %s is not a valid netmask", patcopy);
      mask=ntohl(mask_val.s_addr);   /* We need host byte order */
/*
 *	Calculate the number of bits in the network.
 */
      x = mask;
      for (numbits=0; x != 0; x>>=1) {
         if (x & 0x01) {
            numbits++;
         }
      }
/*
 *      Mask off the network.  Warn if the host bits were non-zero.
 */
      network=ipnet_val & mask;
      if (network != ipnet_val)
         warn_msg("WARNING: host part of %s is non-zero", pattern);
/*
 *      Determine maximum and minimum host values.  We include the host
 *      and broadcast.
 */
      hoststart=0;
      hostend=(1<<(32-numbits))-1;
/*
 *      Calculate all host addresses in the range and feed to add_host()
 *      in dotted-quad format.
 */
      for (i=hoststart; i<=hostend; i++) {
         uint32_t hostip;
         int b1, b2, b3, b4;
         char ipstr[16];

         hostip = network+i;
         b1 = (hostip & 0xff000000) >> 24;
         b2 = (hostip & 0x00ff0000) >> 16;
         b3 = (hostip & 0x0000ff00) >> 8;
         b4 = (hostip & 0x000000ff);
         sprintf(ipstr, "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, timeout);
      }
   } else if (!(regexec(&iprange_pat, patcopy, 0, NULL, 0))) { /* IPstart-IPend */
/*
 *      Get IPstart and IPend as integers.
 */
      cp=strchr(patcopy, '-');
      *(cp++)='\0';     /* patcopy points to IPstart, cp points to IPend */
      if (!(inet_aton(patcopy, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", patcopy);
      hoststart=ntohl(in_val.s_addr);   /* We need host byte order */
      if (!(inet_aton(cp, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", cp);
      hostend=ntohl(in_val.s_addr);     /* We need host byte order */
/*
 *      Calculate all host addresses in the range and feed to add_host()
 *      in dotted-quad format.
 */
      for (i=hoststart; i<=hostend; i++) {
         int b1, b2, b3, b4;
         char ipstr[16];

         b1 = (i & 0xff000000) >> 24;
         b2 = (i & 0x00ff0000) >> 16;
         b3 = (i & 0x0000ff00) >> 8;
         b4 = (i & 0x000000ff);
         sprintf(ipstr, "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, timeout);
      }
   } else {                             /* Single host or IP address */
      add_host(patcopy, timeout);
   }
   free(patcopy);
}

/*
 *	add_host -- Add a new host to the list.
 *
 *	Inputs:
 *
 *	host_name = The Name or IP address of the host.
 *	host_timeout = The initial host timeout in ms.
 *
 *	Returns:
 *
 *	None.
 *
 *	This function is called before the helistptr array is created, so
 *	we use the helist array directly.
 */
void
add_host(const char *host_name, unsigned host_timeout) {
   ip_address *hp=NULL;
   ip_address addr;
   host_entry *he;
   struct timeval now;
   static int num_left=0;	/* Number of free entries left */
   int result;
   char *ga_err_msg;

   if (numeric_flag) {
      if (ipv6_flag) {
         result = inet_pton(AF_INET6, host_name, &(addr.v6));
      } else if (ether_flag) {
         unsigned int mac_b0, mac_b1, mac_b2, mac_b3, mac_b4, mac_b5;
         result = sscanf(host_name, "%x:%x:%x:%x:%x:%x", &mac_b0, &mac_b1,
                         &mac_b2, &mac_b3, &mac_b4, &mac_b5);
         addr.l2.ether_addr_octet[0] = mac_b0;
         addr.l2.ether_addr_octet[1] = mac_b1;
         addr.l2.ether_addr_octet[2] = mac_b2;
         addr.l2.ether_addr_octet[3] = mac_b3;
         addr.l2.ether_addr_octet[4] = mac_b4;
         addr.l2.ether_addr_octet[5] = mac_b5;
      } else {
         result = inet_pton(AF_INET, host_name, &(addr.v4));
      }
      if (result <= 0)
         err_sys("inet_pton failed for \"%s\"", host_name);
   } else {
      if (ipv6_flag) {
         hp = get_host_address(host_name, AF_INET6, &addr, &ga_err_msg);
      } else {
         hp = get_host_address(host_name, AF_INET, &addr, &ga_err_msg);
      }
      if (hp == NULL)
         err_msg("get_host_address failed for \"%s\": %s", host_name,
                 ga_err_msg);
   }

   if (!num_left) {	/* No entries left, allocate some more */
      if (helist)
         helist=Realloc(helist, (num_hosts * sizeof(host_entry)) +
                        REALLOC_COUNT*sizeof(host_entry));
      else
         helist=Malloc(REALLOC_COUNT*sizeof(host_entry));
      num_left = REALLOC_COUNT;
   }

   he = helist + num_hosts;	/* Would array notation be better? */
   num_hosts++;
   num_left--;

   Gettimeofday(&now);

   he->n = num_hosts;
   if (ipv6_flag) {
      memcpy(&(he->addr.v6), &(addr.v6), sizeof(struct in6_addr));
   } else if (ether_flag) {
      memcpy(&(he->addr.l2), &(addr.l2), sizeof(struct ether_addr));
   } else {
      memcpy(&(he->addr.v4), &(addr.v4), sizeof(struct in_addr));
   }
   he->live = 1;
   he->timeout = host_timeout * 1000;	/* Convert from ms to us */
   he->num_sent = 0;
   he->num_recv = 0;
   he->last_send_time.tv_sec=0;
   he->last_send_time.tv_usec=0;
}

/*
 * 	remove_host -- Remove the specified host from the list
 *
 *	inputs:
 *
 *	he = Pointer to host entry to remove.
 *
 *	If the host being removed is the one pointed to by the cursor, this
 *	function updates cursor so that it points to the next entry.
 */
void
remove_host(host_entry **he) {
   if ((*he)->live) {
      (*he)->live = 0;
      live_count--;
      if (*he == *cursor)
         advance_cursor();
      if (debug) {print_times(); printf("remove_host: live_count now %d\n", live_count);}
   } else {
      if (verbose > 1)
         warn_msg("***\tremove_host called on non-live host entry: SHOULDN'T HAPPEN");
   }
}

/*
 *	advance_cursor -- Advance the cursor to point at next live entry
 *
 *	Inputs:
 *
 *	None.
 *
 *	Does nothing if there are no live entries in the list.
 */
void
advance_cursor(void) {
   if (live_count) {
      do {
         if (cursor == (helistptr+(num_hosts-1)))
            cursor = helistptr;	/* Wrap round to beginning */
         else
            cursor++;
      } while (!(*cursor)->live);
   } /* End If */
   if (debug) {print_times(); printf("advance_cursor: cursor now %d\n", (*cursor)->n);}
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
 *	find_host	-- Find a host in the list
 *
 *	Inputs:
 *
 *	he 	Pointer to the current position in the list.  Search runs
 *		backwards starting from this point.
 *	addr 	The source IP address that the packet came from.
 *	packet_in The received packet data.
 *	n	The length of the received packet.
 *
 *	Returns a pointer to the host entry associated with the specified IP
 *	or NULL if no match found.
 *
 *	This routine will normally find the host by IP address by comparing
 *	"addr" against "he->addr" for each entry in the list.  In this case,
 *	"packet_in" and "n" are not used.
 */
host_entry *
find_host(host_entry **he, ip_address *addr,
          const unsigned char *packet_in, int n) {
   host_entry **p;
   int found = 0;
   unsigned iterations = 0;	/* Used for debugging */
/*
 *      Don't try to match if host ptr is NULL.
 *      This should never happen, but we check just in case.
 */
   if (*he == NULL) {
      return NULL;
   }
/*
 *	Try to match against out host list.
 */
   p = he;

   do {
      iterations++;
      if ((*p)->addr.v4.s_addr == addr->v4.s_addr) {
         found = 1;
      } else {
         if (p == helistptr) {
            p = helistptr + (num_hosts-1);	/* Wrap round to end */
         } else {
            p--;
         }
      }
   } while (!found && p != he);

   if (debug) {print_times(); printf("find_host: found=%d, iterations=%u\n", found, iterations);}

   if (iterations > max_iter)
      max_iter=iterations;

   if (found)
      return *p;
   else
      return NULL;
}

/*
 *	recvfrom_wto -- Receive packet with timeout
 *
 *	Inputs:
 *
 *	s	= Socket file descriptor.
 *	buf	= Buffer to receive data read from socket.
 *	len	= Size of buffer.
 *	saddr	= Socket structure.
 *	tmo	= Select timeout in us.
 *
 *	Returns number of characters received, or -1 for timeout.
 */
void
recvfrom_wto(int s, unsigned char *buf, int len, struct sockaddr *saddr,
             int tmo) {
   fd_set readset;
   struct timeval to;
   int n;

   FD_ZERO(&readset);
   FD_SET(s, &readset);
   to.tv_sec  = tmo/1000000;
   to.tv_usec = (tmo - 1000000*to.tv_sec);
   n = select(s+1, &readset, NULL, NULL, &to);
   if (debug) {print_times(); printf("recvfrom_wto: select end, tmo=%d, n=%d\n", tmo, n);}
   if (n < 0) {
      err_sys("select");
   } else if (n == 0) {
      return;	/* Timeout */
   }
   if ((pcap_dispatch(handle, -1, callback, NULL)) < 0)
      err_sys("pcap_dispatch: %s\n", pcap_geterr(handle));
}

/*
 *	timeval_diff -- Calculates the difference between two timevals
 *	and returns this difference in a third timeval.
 *
 *	Inputs:
 *
 *	a	= First timeval
 *	b	= Second timeval
 *	diff	= Difference between timevals (a - b).
 */
void
timeval_diff(const struct timeval *a, const struct timeval *b,
             struct timeval *diff) {
   struct timeval temp;

   temp.tv_sec = b->tv_sec;
   temp.tv_usec = b->tv_usec;

   /* Perform the carry for the later subtraction by updating b. */
   if (a->tv_usec < temp.tv_usec) {
     int nsec = (temp.tv_usec - a->tv_usec) / 1000000 + 1;
     temp.tv_usec -= 1000000 * nsec;
     temp.tv_sec += nsec;
   }
   if (a->tv_usec - temp.tv_usec > 1000000) {
     int nsec = (a->tv_usec - temp.tv_usec) / 1000000;
     temp.tv_usec += 1000000 * nsec;
     temp.tv_sec -= nsec;
   }

   /* Compute the time difference
      tv_usec is certainly positive. */
   diff->tv_sec = a->tv_sec - temp.tv_sec;
   diff->tv_usec = a->tv_usec - temp.tv_usec;
}

/*
 *	dump_list -- Display contents of host list for debugging
 *
 *	Inputs:
 *
 *	None.
 */
void
dump_list(void) {
   int i;

   printf("Host List:\n\n");
   printf("Entry\tIP Address\n");
   for (i=0; i<num_hosts; i++)
      printf("%u\t%s\n", helistptr[i]->n, my_ntoa(helistptr[i]->addr));
   printf("\nTotal of %u host entries.\n\n", num_hosts);
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
 *	process_options	--	Process options and arguments.
 *
 *	Inputs:
 *
 *	argc	Command line arg count
 *	argv	Command line args
 *
 *	Returns:
 *
 *	None.
 */
void
process_options(int argc, char *argv[]) {
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
            arp_scan_version();
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
}

/*
 *	arp_scan_version -- display version information
 *
 *	Inputs:
 *
 *	None.
 *
 *	This displays the arp-scan version information.
 */
void
arp_scan_version (void) {
   fprintf(stderr, "%s\n\n", PACKAGE_STRING);
   fprintf(stderr, "Copyright (C) 2005-2006 Roy Hills, NTA Monitor Ltd.\n");
   fprintf(stderr, "\n");
/* We use rcsid here to prevent it being optimised away */
   fprintf(stderr, "%s\n", rcsid);
}

/*
 *	get_host_address -- Obtain target host IP address
 *
 *	Inputs:
 *
 *	name		The name to lookup
 *	af		The address family.  Either AF_INET or AF_INET6
 *	addr		Pointer to the IP address buffer
 *	error_msg	The error message, or NULL if no problem.
 *
 *	Returns:
 *
 *	Pointer to the IP address, or NULL if an error occurred.
 *
 *	This function is basically a wrapper for getaddrinfo().
 */
ip_address *
get_host_address(const char *name, int af, ip_address *addr, char **error_msg) {
   static char err[MAXLINE];
   static ip_address ipa;

   struct addrinfo *res;
   struct addrinfo hints;
   struct sockaddr_in sa_in;
   struct sockaddr_in6 sa_in6;
   int result;

   if (addr == NULL)	/* Use static storage if no buffer specified */
      addr = &ipa;

   memset(&hints, '\0', sizeof(hints));
   if (af == AF_INET) {
      hints.ai_family = AF_INET;
   } else if (af == AF_INET6) {
      hints.ai_family = AF_INET6;
   } else {
      err_msg("get_host_address: unknown address family: %d", af);
   }

   result = getaddrinfo(name, NULL, &hints, &res);
   if (result != 0) {	/* Error occurred */
      snprintf(err, MAXLINE, "%s", gai_strerror(result));
      *error_msg = err;
      return NULL;
   }

   if (af == AF_INET) {
      memcpy(&sa_in, res->ai_addr, sizeof(sa_in));
      memcpy(&(addr->v4), &sa_in.sin_addr, sizeof(struct in_addr));
   } else {	/* Must be AF_INET6 */
      memcpy(&sa_in6, res->ai_addr, sizeof(sa_in6));
      memcpy(&(addr->v6), &sa_in6.sin6_addr, sizeof(struct in6_addr));
   }

   freeaddrinfo(res);

   *error_msg = NULL;
   return addr;
}

/*
 *	my_ntoa -- IPv6 compatible inet_ntoa replacement
 *
 *	Inputs:
 *
 *	addr	The IP address (either IPv4 or IPv6)
 *
 *	Returns:
 *
 *	Pointer to the string representation of the IP address.
 */
const char *
my_ntoa(ip_address addr) {
   static char ip_str[MAXLINE];
   const char *cp;

   if (ipv6_flag) {
      cp = inet_ntop(AF_INET6, &addr.v6, ip_str, MAXLINE);
   } else if (ether_flag) {
      sprintf(ip_str, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
              addr.l2.ether_addr_octet[0], addr.l2.ether_addr_octet[1],
              addr.l2.ether_addr_octet[2], addr.l2.ether_addr_octet[3],
              addr.l2.ether_addr_octet[4], addr.l2.ether_addr_octet[5]);
      cp = ip_str;
   } else {
      cp = inet_ntop(AF_INET, &addr.v4, ip_str, MAXLINE);
   }

   return cp;
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

