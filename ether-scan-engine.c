/*
 * The ARP scanner (arp-scan) is Copyright (C) 2005-2006
 * Roy Hills, NTA Monitor Ltd.
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
 * $Id: ether-scan-engine.c 7439 2006-06-01 11:18:42Z rsh $
 *
 * ether-scan-engine -- The Ether Scan Engine
 *
 * Author:	Roy Hills
 * Date:	11 October 2005
 *
 * Usage:
 *    <protocol-specific-scanner> [options] [host...]
 *
 * Description:
 *
 * ether-scan-engine sends probe packets to the specified hosts and displays
 * any responses received.  It is a protocol-neutral engine which needs some
 * protocol specific functions (in a separate source file) to build a working
 * scanner.
 * 
 */

#include "ether-scan-engine.h"

static char const rcsid[] = "$Id: ether-scan-engine.c 7439 2006-06-01 11:18:42Z rsh $";	/* RCS ID for ident(1) */

/* Global variables */
host_entry *helist = NULL;		/* Array of host entries */
host_entry **helistptr;			/* Array of pointers to host entries */
host_entry **cursor;			/* Pointer to current host entry ptr */
unsigned num_hosts = 0;			/* Number of entries in the list */
unsigned responders = 0;		/* Number of hosts which responded */
unsigned live_count;			/* Number of entries awaiting reply */
unsigned max_iter;			/* Max iterations in find_host() */
int verbose=0;				/* Verbose level */
int debug = 0;				/* Debug flag */
pcap_t *handle;				/* pcap handle */
int pcap_fd;				/* Pcap file descriptor */
char filename[MAXLINE];
int filename_flag=0;
int random_flag=0;			/* Randomise the list */
int numeric_flag=0;			/* IP addresses only */
int ipv6_flag=0;			/* IPv6 */
int ether_flag=0;			/* Ethernet addresses */
unsigned interval=0;			/* Desired interval between packets */
unsigned bandwidth=DEFAULT_BANDWIDTH;	/* Bandwidth in bits per sec */

extern unsigned retry;			/* Number of retries */
extern unsigned timeout;		/* Per-host timeout */
extern float backoff_factor;		/* Backoff factor */

static char *ga_err_msg;		/* getaddrinfo error message */

int
main(int argc, char *argv[]) {
   char arg_str[MAXLINE];	/* Args as string for syslog */
   int sockfd;			/* IP socket file descriptor */
   struct sockaddr_in sa_peer;
   struct timeval now;
   unsigned char packet_in[MAXIP];	/* Received packet */
   struct timeval diff;		/* Difference between two timevals */
   int select_timeout;		/* Select timeout */
   ARP_UINT64 loop_timediff;	/* Time since last packet sent in us */
   ARP_UINT64 host_timediff; /* Time since last pkt sent to this host (us) */
   int arg;
   int arg_str_space;		/* Used to avoid buffer overruns when copying */
   struct timeval last_packet_time;	/* Time last packet was sent */
   int req_interval;		/* Requested per-packet interval */
   int cum_err=0;		/* Cumulative timing error */
   struct timeval start_time;	/* Program start time */
   struct timeval end_time;	/* Program end time */
   struct timeval elapsed_time;	/* Elapsed time as timeval */
   double elapsed_seconds;	/* Elapsed time in seconds */
   static int reset_cum_err;
   static int pass_no;
   int first_timeout=1;
   int i;
/*
 *	Open syslog channel and log arguments if required.
 *	We must be careful here to avoid overflowing the arg_str buffer
 *	which could result in a buffer overflow vulnerability.  That's why
 *	we use strncat and keep track of the remaining buffer space.
 */
#ifdef SYSLOG
   openlog("arp-scan", LOG_PID, SYSLOG_FACILITY);
   arg_str[0] = '\0';
   arg_str_space = MAXLINE;	/* Amount of space in the arg_str buffer */
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
 *	Process options.
 */
   process_options(argc, argv);
/*
 *	Get program start time for statistics displayed on completion.
 */
   Gettimeofday(&start_time);
   if (debug) {print_times(); printf("main: Start\n");}
/*
 *	Create packet socket.  This socket is used to send outbound packets.
 */
   if ((sockfd = socket(PF_PACKET, SOCK_DGRAM, 0)) < 0)
      err_sys("socket");
/*
 *	Call protocol-specific initialisation routine to perform any
 *	initial setup required.
 */
   initialise();
/*
 *	Drop privileges.
 */
   if ((setuid(getuid())) < 0) {
      err_sys("setuid");
   }
/*
 *	If we're not reading from a file, then we must have some hosts
 *	given as command line arguments.
 */
   if (!filename_flag) 
      if ((argc - optind) < 1)
         usage(EXIT_FAILURE);
/*
 *	Populate the list from the specified file if --file was specified, or
 *	otherwise from the remaining command line arguments.
 */
   if (filename_flag) {	/* Populate list from file */
      FILE *fp;
      char line[MAXLINE];
      char *cp;

      if ((strcmp(filename, "-")) == 0) {	/* Filename "-" means stdin */
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
   } else {		/* Populate list from command line arguments */
      argv=&argv[optind];
      while (*argv) {
         add_host_pattern(*argv, timeout);
         argv++;
      }
   }
/*
 *	Check that we have at least one entry in the list.
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
 *	Create and initialise array of pointers to host entries.
 */
   helistptr = Malloc(num_hosts * sizeof(host_entry *));
   for (i=0; i<num_hosts; i++)
      helistptr[i] = &helist[i];
/*
 *	Randomise the list if required.
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
 *	Set current host pointer (cursor) to start of list, zero
 *	last packet sent time, and set last receive time to now.
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
         packet_out_len = MINIMUM_FRAME_SIZE;	/* Adjust to minimum size */
      packet_out_len += PACKET_OVERHEAD;        /* Add layer 2 overhead */
      interval = ((ARP_UINT64)packet_out_len * 8 * 1000000) / bandwidth;
      if (verbose) {
         warn_msg("DEBUG: pkt len=%u bytes, bandwidth=%u bps, interval=%u us",
                  packet_out_len, bandwidth, interval);
      }
   }
/*
 *	Display initial message.
 */
   printf("Starting %s with %u hosts (http://www.nta-monitor.com/arp-scan/)\n",
          PACKAGE_STRING, num_hosts);
/*
 *	Display the lists if verbose setting is 3 or more.
 */
   if (verbose > 2)
      dump_list();
/*
 *	Main loop: send packets to all hosts in order until a response
 *	has been received or the host has exhausted its retry limit.
 *
 *	The loop exits when all hosts have either responded or timed out.
 */
   reset_cum_err = 1;
   req_interval = interval;
   while (live_count) {
      if (debug) {print_times(); printf("main: Top of loop.\n");}
/*
 *	Obtain current time and calculate deltas since last packet and
 *	last packet to this host.
 */
      Gettimeofday(&now);
/*
 *	If the last packet was sent more than interval us ago, then we can
 *	potentially send a packet to the current host.
 */
      timeval_diff(&now, &last_packet_time, &diff);
      loop_timediff = (ARP_UINT64)1000000*diff.tv_sec + diff.tv_usec;
      if (loop_timediff >= req_interval) {
         if (debug) {print_times(); printf("main: Can send packet now.  loop_timediff=" ARP_UINT64_FORMAT "\n", loop_timediff);}
/*
 *	If the last packet to this host was sent more than the current
 *	timeout for this host us ago, then we can potentially send a packet
 *	to it.
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
 *	If we've exceeded our retry limit, then this host has timed out so
 *	remove it from the list.  Otherwise, increase the timeout by the
 *	backoff factor if this is not the first packet sent to this host
 *	and send a packet.
 */
            if (verbose && (*cursor)->num_sent > pass_no) {
               warn_msg("---\tPass %d complete", pass_no+1);
               pass_no = (*cursor)->num_sent;
            }
            if ((*cursor)->num_sent >= retry) {
               if (verbose > 1)
                  warn_msg("---\tRemoving host entry %u (%s) - Timeout", (*cursor)->n, my_ntoa((*cursor)->addr));
               if (debug) {print_times(); printf("main: Timing out host %d.\n", (*cursor)->n);}
               remove_host(cursor);	/* Automatically calls advance_cursor() */
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
            } else {	/* Retry limit not reached for this host */
               if ((*cursor)->num_sent)
                  (*cursor)->timeout *= backoff_factor;
               send_packet(sockfd, *cursor, &last_packet_time);
               advance_cursor();
            }
         } else {	/* We can't send a packet to this host yet */
/*
 *	Note that there is no point calling advance_cursor() here because if
 *	host n is not ready to send, then host n+1 will not be ready either.
 */
            select_timeout = (*cursor)->timeout - host_timediff;
            reset_cum_err = 1;	/* Zero cumulative error */
            if (debug) {print_times(); printf("main: Can't send packet to host %d yet. host_timediff=" ARP_UINT64_FORMAT "\n", (*cursor)->n, host_timediff);}
         } /* End If */
      } else {		/* We can't send a packet yet */
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
/*
 * Return immediately if the local add_host function replaces this generic one.
 */
   if (local_add_host(host_name, host_timeout))
      return;

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
 *	"packet_in" and "n" are not used.  However, it is  possible for
 *	the protocol-specific "local_find_host()" routine to override this
 *	generic routine, and the protocol specific routine may use "packet_in"
 *	and "n".
 */
host_entry *
find_host(host_entry **he, ip_address *addr,
          const unsigned char *packet_in, int n) {
   host_entry **p;
   host_entry *ptr;
   int found = 0;
   unsigned iterations = 0;	/* Used for debugging */
/*
 *	Return with the result from local_find_host if the local find_host
 *	function replaces this one.
 */
   if (local_find_host(&ptr, he, addr, packet_in, n)) {
      return ptr;
   }

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
/*   fprintf(stderr, "\n--ipv6 or -6\t\tUse IPv6 protocol. Default is IPv4.\n"); */
/* Call scanner-specific help function */
   local_help();
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
      {"random", no_argument, 0, 'R'},
      {"numeric", no_argument, 0, 'N'},
      {"ipv6", no_argument, 0, '6'},
      {"bandwidth", required_argument, 0, 'B'},
      {0, 0, 0, 0}
   };
   const char *short_options = "f:hr:t:i:b:vVdN6B:";
   int arg;
   int options_index=0;
/*
 * Return immediately if the local process_options function replaces this
 * generic one.
 */
   if (local_process_options(argc, argv))
      return;

   while ((arg=getopt_long_only(argc, argv, short_options, long_options, &options_index)) != -1) {
      switch (arg) {
         char interval_str[MAXLINE];    /* --interval argument */
         size_t interval_len;   /* --interval argument length */
         char bandwidth_str[MAXLINE];   /* --bandwidth argument */
         size_t bandwidth_len;  /* --bandwidth argument length */

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
         case 'R':      /* --random */
            random_flag=1;
            break;
         case 'N':	/* --numeric */
            numeric_flag=1;
            break;
         case '6':      /* --ipv6 */
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
         default:	/* Unknown option */
            usage(EXIT_FAILURE);
            break;
      }
   }
}

/*
 *	ether_scan_version -- display version information
 *
 *	Inputs:
 *
 *	None.
 *
 *	This displays the ether-scan version information and also calls the
 *	protocol-specific version function to display the protocol-specific
 *	version information.
 */
void
ether_scan_version (void) {
   fprintf(stderr, "%s\n\n", PACKAGE_STRING);
   fprintf(stderr, "Copyright (C) 2005-2006 Roy Hills, NTA Monitor Ltd.\n");
   fprintf(stderr, "\n");
/* We use rcsid here to prevent it being optimised away */
   fprintf(stderr, "%s\n", rcsid);
/* Call scanner-specific version routine */
   local_version();
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
