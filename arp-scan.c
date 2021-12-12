/*
 * The ARP Scanner (arp-scan) is Copyright (C) 2005-2019 Roy Hills
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

/* Global variables */
static host_entry *helist = NULL;	/* Array of host entries */
static host_entry **helistptr;		/* Array of pointers to host entries */
static host_entry **cursor;		/* Pointer to current host entry ptr */
static unsigned num_hosts = 0;		/* Number of entries in the list */
static unsigned responders = 0;		/* Number of hosts which responded */
static unsigned live_count;		/* Number of entries awaiting reply */
static int verbose=0;			/* Verbose level */
static char filename[MAXLINE];		/* Target list file name */
static int filename_flag=0;		/* Set if using target list file */
static int random_flag=0;		/* Randomise the list */
static int numeric_flag=0;		/* IP addresses only */
static unsigned interval=0;		/* Desired interval between packets */
static unsigned bandwidth=DEFAULT_BANDWIDTH; /* Bandwidth in bits per sec */
static unsigned retry = DEFAULT_RETRY;	/* Number of retries */
static unsigned timeout = DEFAULT_TIMEOUT; /* Per-host timeout */
static float backoff_factor = DEFAULT_BACKOFF_FACTOR;	/* Backoff factor */
static int snaplen = SNAPLEN;		/* Pcap snap length */
static char *if_name=NULL;		/* Interface name, e.g. "eth0" */
static int quiet_flag=0;		/* Don't decode the packet */
static int ignore_dups=0;		/* Don't display duplicate packets */
static uint32_t arp_spa;		/* Source IP address */
static int arp_spa_flag=0;		/* Source IP address specified */
static int arp_spa_is_tpa=0;		/* Source IP is dest IP */
static unsigned char arp_sha[ETH_ALEN];	/* Source Ethernet MAC Address */
static int arp_sha_flag=0;		/* Source MAC address specified */
static char ouifilename[MAXLINE];	/* OUI filename */
static char iabfilename[MAXLINE];	/* IAB filename */
static char macfilename[MAXLINE];	/* MAC filename */
static char pcap_savefile[MAXLINE];	/* pcap savefile filename */
static int arp_op=DEFAULT_ARP_OP;	/* ARP Operation code */
static int arp_hrd=DEFAULT_ARP_HRD;	/* ARP hardware type */
static int arp_pro=DEFAULT_ARP_PRO;	/* ARP protocol */
static int arp_hln=DEFAULT_ARP_HLN;	/* Hardware address length */
static int arp_pln=DEFAULT_ARP_PLN;	/* Protocol address length */
static int eth_pro=DEFAULT_ETH_PRO;	/* Ethernet protocol type */
static unsigned char arp_tha[6] = {0, 0, 0, 0, 0, 0};
static unsigned char target_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static unsigned char source_mac[6];
static int source_mac_flag = 0;
static unsigned char *padding=NULL;
static size_t padding_len=0;
static int localnet_flag=0;		/* Scan local network */
static int llc_flag=0;			/* Use 802.2 LLC with SNAP */
static int ieee_8021q_vlan=-1;		/* Use 802.1Q VLAN tagging if >= 0 */
static int pkt_write_file_flag=0;	/* Write packet to file flag */
static int pkt_read_file_flag=0;	/* Read packet from file flag */
static char pkt_filename[MAXLINE];	/* Read/Write packet to file filename */
static int write_pkt_to_file=0;		/* Write packet to file for debugging */
static int rtt_flag=0;			/* Display round-trip time */
static pcap_dumper_t *pcap_dump_handle = NULL;	/* pcap savefile handle */
static int plain_flag=0;		/* Only show host information */
unsigned int random_seed=0;
static unsigned retry_send = DEFAULT_RETRY_SEND; /* Number of send packet retries */
static unsigned retry_send_interval = DEFAULT_RETRY_SEND_INTERVAL; /* Interval in seconds between send packet retries */

int
main(int argc, char *argv[]) {
   struct timeval now;
   struct timeval diff;         /* Difference between two timevals */
   int select_timeout;          /* Select timeout */
   uint64_t loop_timediff;    /* Time since last packet sent in us */
   uint64_t host_timediff; /* Time since last pkt sent to this host (us) */
   struct timeval last_packet_time;     /* Time last packet was sent */
   int req_interval;		/* Requested per-packet interval */
   int cum_err=0;               /* Cumulative timing error */
   struct timeval start_time;   /* Program start time */
   struct timeval end_time;     /* Program end time */
   struct timeval elapsed_time; /* Elapsed time as timeval */
   double elapsed_seconds;      /* Elapsed time in seconds */
   int reset_cum_err;
   int pass_no = 0;
   int first_timeout=1;
   unsigned i;
   char errbuf[PCAP_ERRBUF_SIZE];
   struct bpf_program filter;
   char *filter_string;
   bpf_u_int32 netmask;
   bpf_u_int32 localnet;
   int datalink;
   int ret_status = 0;
   int pcap_fd;			/* Pcap file descriptor */
   unsigned char interface_mac[ETH_ALEN];
   pcap_t *pcap_handle;		/* pcap handle */
   struct in_addr interface_ip_addr;
/*
 *      Initialise file names to the empty string.
 */
   ouifilename[0] = '\0';
   iabfilename[0] = '\0';
   macfilename[0] = '\0';
   pcap_savefile[0] = '\0';
/*
 *      Process options.
 */
   process_options(argc, argv);
/*
 *      Get program start time for statistics displayed on completion.
 */
   Gettimeofday(&start_time);
/*
 * Open the network device for reading with pcap, or the pcap file if we
 * have specified --readpktfromfile. If we are writing packets to a binary
 * file, then set pcap_handle to NULL as we don't need to read packets in
 * this case.
 */
   if (pkt_read_file_flag) {
      if (!(pcap_handle = pcap_open_offline(pkt_filename, errbuf)))
         err_msg("pcap_open_offline: %s", errbuf);
   } else if (!pkt_write_file_flag) {
      /*
       * Determine network interface to use. If the interface was specified
       * with the --interface option then use that, otherwise use
       * my_lookupdev() to pick a suitable interface.
       */
      if (!if_name) {
         if (!(if_name=my_lookupdev(errbuf))) {
            err_msg("my_lookupdev: %s", errbuf);
         }
      }
      if (!(pcap_handle = pcap_create(if_name, errbuf)))
         err_msg("pcap_create: %s", errbuf);
      if ((pcap_set_snaplen(pcap_handle, snaplen)) < 0)
         err_msg("pcap_set_snaplen: %s", pcap_geterr(pcap_handle));
      if ((pcap_set_promisc(pcap_handle, PROMISC)) < 0)
         err_msg("pcap_set_promisc: %s", pcap_geterr(pcap_handle));
      if ((pcap_set_immediate_mode(pcap_handle, 1)) < 0)
         err_msg("pcap_set_immediate_mode: %s", pcap_geterr(pcap_handle));
      if ((pcap_set_timeout(pcap_handle, TO_MS)) < 0) /* Is this still needed? */
         err_msg("pcap_set_timeout: %s", pcap_geterr(pcap_handle));
      ret_status = pcap_activate(pcap_handle);
      if (ret_status < 0) {		/* Error from pcap_activate() */
         char *cp;

         cp = pcap_geterr(pcap_handle);
         if (ret_status == PCAP_ERROR)
            err_msg("pcap_activate: %s", cp);
         else if ((ret_status == PCAP_ERROR_NO_SUCH_DEVICE ||
                   ret_status == PCAP_ERROR_PERM_DENIED) && *cp != '\0')
            err_msg("pcap_activate: %s: %s\n(%s)", if_name,
                    pcap_statustostr(ret_status), cp);
         else
            err_msg("pcap_activate: %s: %s", if_name,
                    pcap_statustostr(ret_status));
      } else if (ret_status > 0) {	/* Warning from pcap_activate() */
         char *cp;

         cp = pcap_geterr(pcap_handle);
         if (ret_status == PCAP_WARNING)
            warn_msg("pcap_activate: %s", cp);
         else if (ret_status == PCAP_WARNING_PROMISC_NOTSUP && *cp != '\0')
            warn_msg("pcap_activate: %s: %s\n(%s)", if_name,
                     pcap_statustostr(ret_status), cp);
         else
            warn_msg("pcap_activate: %s: %s", if_name,
                     pcap_statustostr(ret_status));
      }
      /*
       * Obtain the MAC address for the selected interface, and use this
       * as the default value for the source hardware addresses in the frame
       * header and ARP packet if the user has not specified their values.
       *
       * Die with an error if we can't get the MAC address, as this
       * indicates that the interface doesn't have a MAC address, so is
       * probably not a compatible interface type.
       */
      get_hardware_address(if_name, interface_mac);
      if (interface_mac[0]==0 && interface_mac[1]==0 &&
          interface_mac[2]==0 && interface_mac[3]==0 &&
          interface_mac[4]==0 && interface_mac[5]==0) {
         err_msg("ERROR: Could not obtain MAC address for interface %s",
                 if_name);
      }
      if (source_mac_flag == 0)
         memcpy(source_mac, interface_mac, ETH_ALEN);
      if (arp_sha_flag == 0)
         memcpy(arp_sha, interface_mac, ETH_ALEN);
      /*
       * Obtain the interface IP address, and use that as the default value
       * if the user has not manually specified the ARP source address.
       *
       * Give a warning and use 0.0.0.0 if the interface has no IP address.
       */
      ret_status = get_source_ip(if_name, &interface_ip_addr);
      if (arp_spa_flag == 0) {
         if (ret_status == -1) {
            warn_msg("WARNING: Could not obtain IP address for interface %s. "
                     "Using 0.0.0.0 for", if_name);
            warn_msg("the source address, which may not be what you want.");
            warn_msg("Either configure %s with an IP address, or manually specify"
                     " the address", if_name);
            warn_msg("with the --arpspa option.");
         }
         memcpy(&arp_spa, &(interface_ip_addr.s_addr), sizeof(arp_spa));
      }
   } else {
      pcap_handle = NULL;
   }
/*
 *	If we are reading data with pcap, get and display the datalink details
 */
   if (pcap_handle) {
      if ((datalink=pcap_datalink(pcap_handle)) < 0)
         err_msg("pcap_datalink: %s", pcap_geterr(pcap_handle));
      if (!plain_flag) {
         if (!pkt_read_file_flag) {
            printf("Interface: %s, type: %s, "
                   "MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x, IPv4: %s\n",
                   if_name, pcap_datalink_val_to_name(datalink),
                   interface_mac[0], interface_mac[1], interface_mac[2],
                   interface_mac[3], interface_mac[4], interface_mac[5],
                   (interface_ip_addr.s_addr==0) ? "(none)" : my_ntoa(interface_ip_addr));
         } else {
            printf("Interface: pcap file\n");
         }
      }
      if (datalink != DLT_EN10MB) {
         warn_msg("WARNING: Unsupported datalink type");
      }
   }
/*
 *	If we are reading from a network device, then get the associated file
 *	descriptor and configure it, determine the interface IP network and
 *	netmask, and install a pcap filter to receive only ARP responses.
 *	If we are reading from a pcap file, or writing to a binary file, just
 *	set the file descriptor to -1 to indicate that it is not associated
 *	with a network device.
 */
   if (!pkt_read_file_flag && !pkt_write_file_flag) {
      if ((pcap_fd=pcap_get_selectable_fd(pcap_handle)) < 0)
         err_msg("pcap_fileno: %s", pcap_geterr(pcap_handle));
      if ((pcap_setnonblock(pcap_handle, 1, errbuf)) < 0)
         err_msg("pcap_setnonblock: %s", errbuf);

      if (pcap_lookupnet(if_name, &localnet, &netmask, errbuf) < 0) {
         memset(&localnet, '\0', sizeof(localnet));
         memset(&netmask, '\0', sizeof(netmask));
         if (localnet_flag) {
            warn_msg("ERROR: Could not obtain interface IP address and netmask");
            err_msg("ERROR: pcap_lookupnet: %s", errbuf);
         }
      }
/*
 *	The filter string selects packets addressed to the ARP source address
 *	that are Ethernet-II ARP packets, 802.3 LLC/SNAP ARP packets,
 *	802.1Q tagged ARP packets or 802.1Q tagged 802.3 LLC/SNAP ARP packets.
 */
      filter_string=make_message("ether dst %.2x:%.2x:%.2x:%.2x:%.2x:%.2x and "
                                 "(arp or (ether[14:4]=0xaaaa0300 and "
                                 "ether[20:2]=0x0806) or (ether[12:2]=0x8100 "
                                 "and ether[16:2]=0x0806) or "
                                 "(ether[12:2]=0x8100 and "
                                 "ether[18:4]=0xaaaa0300 and "
                                 "ether[24:2]=0x0806))",
                                 arp_sha[0], arp_sha[1],
                                 arp_sha[2], arp_sha[3],
                                 arp_sha[4], arp_sha[5]);
      if (verbose > 1)
         warn_msg("DEBUG: pcap filter string: \"%s\"", filter_string);
      if ((pcap_compile(pcap_handle, &filter, filter_string, OPTIMISE,
           netmask)) < 0)
         err_msg("pcap_compile: %s", pcap_geterr(pcap_handle));
      free(filter_string);
      if ((pcap_setfilter(pcap_handle, &filter)) < 0)
         err_msg("pcap_setfilter: %s", pcap_geterr(pcap_handle));
   } else {	/* Reading packets from file */
      pcap_fd = -1;
   }
/*
 *      Drop SUID privileges.
 */
   if ((setuid(getuid())) < 0) {
      err_sys("setuid");
   }
/*
 *	Open pcap savefile is the --pcapsavefile (-W) option was specified
 */
   if (*pcap_savefile != '\0') {
      if (!(pcap_dump_handle=pcap_dump_open(pcap_handle, pcap_savefile))) {
         err_msg("pcap_dump_open: %s", pcap_geterr(pcap_handle));
      }
   }
/*
 *      Check that the combination of specified options and arguments is
 *      valid.
 */
   if (interval && bandwidth != DEFAULT_BANDWIDTH)
      err_msg("ERROR: You cannot specify both --bandwidth and --interval.");
   if (localnet_flag) {
      if ((argc - optind) > 0)
         err_msg("ERROR: You can not specify targets with the --localnet option");
      if (filename_flag)
         err_msg("ERROR: You can not specify both --file and --localnet options");
   }
/*
 *      If we're not reading from a file, and --localnet was not specified, then
 *	we must have some hosts given as command line arguments.
 */
   if (!filename_flag && !localnet_flag)
      if ((argc - optind) < 1)
         usage(EXIT_FAILURE, 0);
/*
 * Create MAC/Vendor hash table if quiet is not in effect.
 */
   if (!quiet_flag) {
      char *fn;
      int count;

      if ((hcreate(HASH_TABLE_SIZE)) == 0)
         err_sys("hcreate");

      fn = get_mac_vendor_filename(ouifilename, DATADIR, OUIFILENAME);
      count = add_mac_vendor(fn);
      if (verbose > 1 && count > 0)
         warn_msg("DEBUG: Loaded %d IEEE OUI/Vendor entries from %s.",
                  count, fn);
      free(fn);

      fn = get_mac_vendor_filename(iabfilename, DATADIR, IABFILENAME);
      count = add_mac_vendor(fn);
      if (verbose > 1 && count > 0)
         warn_msg("DEBUG: Loaded %d IEEE IAB/Vendor entries from %s.",
                  count, fn);
      free(fn);

      fn = get_mac_vendor_filename(macfilename, DATADIR, MACFILENAME);
      count = add_mac_vendor(fn);
      if (verbose > 1 && count > 0)
         warn_msg("DEBUG: Loaded %d MAC/Vendor entries from %s.",
                  count, fn);
      free(fn);
   }
/*
 *      Populate the list from the specified file if --file was specified, or
 *	from the interface address and mask if --localnet was specified, or
 *      otherwise from the remaining command line arguments.
 */
   if (filename_flag) { /* Populate list from file */
      FILE *fp;
      char line[MAXLINE];
      char *cp;

      if ((strcmp(filename, "-")) == 0) {       /* Filename "-" means stdin */
         fp = stdin;
      } else {
         if ((fp = fopen(filename, "r")) == NULL) {
            err_sys("fopen");
         }
      }

      while (fgets(line, MAXLINE, fp)) {
         for (cp = line; !isspace((unsigned char)*cp) && *cp != '\0'; cp++)
            ;
         *cp = '\0';
         add_host_pattern(line, timeout);
      }
      if (fp != stdin) {
         fclose(fp);
      }
   } else if (localnet_flag) {	/* Populate list from i/f addr & mask */
      struct in_addr if_network;
      struct in_addr if_netmask;
      char *c_network;
      char *c_netmask;
      const char *cp;
      char localnet_descr[32];

      if_network.s_addr = localnet;
      if_netmask.s_addr = netmask;
      cp = my_ntoa(if_network);
      c_network = make_message("%s", cp);
      cp = my_ntoa(if_netmask);
      c_netmask = make_message("%s", cp);
      snprintf(localnet_descr, 32, "%s:%s", c_network, c_netmask);
      free(c_network);
      free(c_netmask);

      if (verbose) {
         warn_msg("Using %s for localnet", localnet_descr);
      }
      add_host_pattern(localnet_descr, timeout);
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
      err_msg("ERROR: No hosts to process.");
/*
 *	If --writepkttofile was specified, open the specified output file.
 */
   if (pkt_write_file_flag) {
      write_pkt_to_file = open(pkt_filename, O_WRONLY|O_CREAT|O_TRUNC, 0666);
      if (write_pkt_to_file == -1)
         err_sys("open %s", pkt_filename);
   }
/*
 *      Create and initialise array of pointers to host entries.
 */
   helistptr = Malloc(num_hosts * sizeof(host_entry *));
   for (i=0; i<num_hosts; i++)
      helistptr[i] = &helist[i];
/*
 *      Randomise the list if required.
 *	Uses Knuth's shuffle algorithm.
 */
   if (random_flag) {
      int r;
      host_entry *temp;
/*
 *      Seed random number generator.
 *      If the random seed has been specified (is non-zero), then use that.
 *      Otherwise, seed the RNG with an unpredictable value.
 */
      if (!random_seed) {
         struct timeval tv;

         Gettimeofday(&tv);
         random_seed = tv.tv_usec ^ getpid();	/* Unpredictable value */
      }
      init_genrand(random_seed);

      for (i=num_hosts-1; i>0; i--) {
         r = (int)(genrand_real2() * i);  /* 0<=r<i */
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

      packet_out_len=send_packet(NULL, NULL, NULL); /* Get packet data size */
      if (packet_out_len < MINIMUM_FRAME_SIZE)
         packet_out_len = MINIMUM_FRAME_SIZE;   /* Adjust to minimum size */
      packet_out_len += PACKET_OVERHEAD;	/* Add layer 2 overhead */
      interval = ((uint64_t)packet_out_len * 8 * 1000000) / bandwidth;
      if (verbose > 1) {
         warn_msg("DEBUG: pkt len=%u bytes, bandwidth=%u bps, interval=%u us",
                  packet_out_len, bandwidth, interval);
      }
   }
/*
 *      Display initial message.
 */
   if (!plain_flag) {
      printf("Starting %s with %u hosts (https://github.com/royhills/arp-scan)\n",
          PACKAGE_STRING, num_hosts);
   }
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
      loop_timediff = (uint64_t)1000000*diff.tv_sec + diff.tv_usec;
      if (loop_timediff >= (unsigned)req_interval) {
/*
 *      If the last packet to this host was sent more than the current
 *      timeout for this host us ago, then we can potentially send a packet
 *      to it.
 */
         timeval_diff(&now, &((*cursor)->last_send_time), &diff);
         host_timediff = (uint64_t)1000000*diff.tv_sec + diff.tv_usec;
         if (host_timediff >= (*cursor)->timeout) {
            if (reset_cum_err) {
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
            select_timeout = req_interval;
/*
 *      If we've exceeded our retry limit, then this host has timed out so
 *      remove it from the list. Otherwise, increase the timeout by the
 *      backoff factor if this is not the first packet sent to this host
 *      and send a packet.
 */
            if (verbose && (*cursor)->num_sent > pass_no) {
               warn_msg("---\tPass %d complete", pass_no+1);
               pass_no = (*cursor)->num_sent;
            }
            if ((*cursor)->num_sent >= retry) {
               if (verbose > 1)
                  warn_msg("---\tRemoving host %s - Timeout",
                            my_ntoa((*cursor)->addr));
               remove_host(cursor);     /* Automatically calls advance_cursor() */
               if (first_timeout) {
                  timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                  host_timediff = (uint64_t)1000000*diff.tv_sec +
                                  diff.tv_usec;
                  while (host_timediff >= (*cursor)->timeout && live_count) {
                     if ((*cursor)->live) {
                        if (verbose > 1)
                           warn_msg("---\tRemoving host %s - Catch-Up Timeout",
                                    my_ntoa((*cursor)->addr));
                        remove_host(cursor);
                     } else {
                        advance_cursor();
                     }
                     timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                     host_timediff = (uint64_t)1000000*diff.tv_sec +
                                     diff.tv_usec;
                  }
                  first_timeout=0;
               }
               Gettimeofday(&last_packet_time);
            } else {    /* Retry limit not reached for this host */
               if ((*cursor)->num_sent)
                  (*cursor)->timeout *= backoff_factor;
               send_packet(pcap_handle, *cursor, &last_packet_time);
               advance_cursor();
            }
         } else {       /* We can't send a packet to this host yet */
/*
 *      Note that there is no point calling advance_cursor() here because if
 *      host n is not ready to send, then host n+1 will not be ready either.
 */
            select_timeout = (*cursor)->timeout - host_timediff;
            reset_cum_err = 1;  /* Zero cumulative error */
         } /* End If */
      } else {          /* We can't send a packet yet */
         select_timeout = req_interval - loop_timediff;
      } /* End If */
      recvfrom_wto(pcap_fd, select_timeout, pcap_handle);
   } /* End While */

   if (!plain_flag) {
      printf("\n");        /* Ensure we have a blank line */
   }

   clean_up(pcap_handle);
   if (write_pkt_to_file)
      close(write_pkt_to_file);

   Gettimeofday(&end_time);
   timeval_diff(&end_time, &start_time, &elapsed_time);
   elapsed_seconds = (elapsed_time.tv_sec*1000 +
                      elapsed_time.tv_usec/1000) / 1000.0;

   if (!plain_flag) {
      printf("Ending %s: %u hosts scanned in %.3f seconds (%.2f hosts/sec). %u responded\n",
             PACKAGE_STRING, num_hosts, elapsed_seconds,
             num_hosts/elapsed_seconds, responders);
   }
   return 0;
}

/*
 *	display_packet -- Check and display received packet
 *
 *	Inputs:
 *
 *	he		The host entry corresponding to the received packet
 *	arpei		ARP packet structure
 *	extra_data	Extra data after ARP packet (padding)
 *	extra_data_len	Length of extra data
 *	framing		Framing type (e.g. Ethernet II, LLC)
 *	vlan_id		802.1Q VLAN identifier, or -1 if not 802.1Q
 *	frame_hdr	The Ethernet frame header
 *	pcap_header	The PCAP header struct
 *
 *      Returns:
 *
 *      None.
 *
 *      This checks the received packet and displays details of what
 *      was received in the format: <IP-Address><TAB><Details>.
 */
void
display_packet(host_entry *he, arp_ether_ipv4 *arpei,
               const unsigned char *extra_data, size_t extra_data_len,
               int framing, int vlan_id, ether_hdr *frame_hdr,
               const struct pcap_pkthdr *pcap_header) {
   char *msg;
   char *cp;
   char *cp2;
   int nonzero=0;
/*
 *	Set msg to the IP address of the host entry and a tab.
 */
   msg = make_message("%s\t", my_ntoa(he->addr));
/*
 *	Decode ARP packet
 */
   cp = msg;
   msg = make_message("%s%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", cp,
                      arpei->ar_sha[0], arpei->ar_sha[1],
                      arpei->ar_sha[2], arpei->ar_sha[3],
                      arpei->ar_sha[4], arpei->ar_sha[5]);
   free(cp);
/*
 *	Check that the source address in the Ethernet frame header is the same
 *	as ar$sha in the ARP packet, and display the Ethernet source address
 *	if it is different.
 */
   if ((memcmp(arpei->ar_sha, frame_hdr->src_addr, ETH_ALEN)) != 0) {
      cp = msg;
      msg = make_message("%s (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x)", cp,
                         frame_hdr->src_addr[0], frame_hdr->src_addr[1],
                         frame_hdr->src_addr[2], frame_hdr->src_addr[3],
                         frame_hdr->src_addr[4], frame_hdr->src_addr[5]);
      free(cp);
   }
/*
 *	Find vendor from hash table and add to message if quiet is not in
 *	effect.
 *
 *	We start with more specific matches (against larger parts of the
 *	hardware address), and work towards less specific matches until
 *	we find a match or exhaust all possible matches.
 */
   if (!quiet_flag) {
      char oui_string[13];	/* Space for full hw addr plus NULL */
      const char *vendor=NULL;
      int oui_end=12;
      ENTRY hash_query;
      ENTRY *hash_result;

      snprintf(oui_string, 13, "%.2X%.2X%.2X%.2X%.2X%.2X",
               arpei->ar_sha[0], arpei->ar_sha[1], arpei->ar_sha[2],
               arpei->ar_sha[3], arpei->ar_sha[4], arpei->ar_sha[5]);
      while (vendor == NULL && oui_end > 1) {
         oui_string[oui_end] = '\0';	/* Truncate oui string */
         hash_query.key = oui_string;
         hash_result = hsearch(hash_query, FIND);
         if (hash_result) {
            vendor = hash_result->data;
         } else {
            vendor = NULL;
         }
         oui_end--;
      }
      cp = msg;
      if (vendor)
         msg = make_message("%s\t%s", cp, vendor);
      else
         /* Of the first octet of the address, check the second-least-significant bit */
         if (arpei->ar_sha[0] & (1<<1))
             msg = make_message("%s\t%s", cp, "(Unknown: locally administered)");
         else
             msg = make_message("%s\t%s", cp, "(Unknown)");
      free(cp);
/*
 *	Check that any data after the ARP packet is zero.
 *	If it is non-zero, and verbose is selected, then print the padding.
 */
      if (extra_data_len > 0) {
         unsigned i;
         const unsigned char *ucp = extra_data;

         for (i=0; i<extra_data_len; i++) {
            if (ucp[i] != '\0') {
               nonzero=1;
               break;
            }
         }
      }
      if (nonzero && verbose) {
         cp = msg;
         cp2 = hexstring(extra_data, extra_data_len);
         msg = make_message("%s\tPadding=%s", cp, cp2);
         free(cp2);
         free(cp);
      }
/*
 *	If the framing type is not Ethernet II, then report the framing type.
 */
      if (framing != FRAMING_ETHERNET_II) {
         cp = msg;
         if (framing == FRAMING_LLC_SNAP) {
            msg = make_message("%s (802.2 LLC/SNAP)", cp);
         }
         free(cp);
      }
/*
 *	If the packet uses 802.1Q VLAN tagging, report the VLAN ID.
 */
      if (vlan_id != -1) {
         cp = msg;
         msg = make_message("%s (802.1Q VLAN=%d)", cp, vlan_id);
         free(cp);
      }
/*
 *	If the ARP protocol type is not IP (0x0800), report it.
 *	This can occur with trailer encapsulation ARP replies.
 */
      if (ntohs(arpei->ar_pro) != 0x0800) {
         cp = msg;
         msg = make_message("%s (ARP Proto=0x%04x)", cp, ntohs(arpei->ar_pro));
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
/*
 *	If the rtt_flag is set, calculate and report the packet round-trip
 *	time.
 */
      if (rtt_flag) {
         struct timeval rtt;
         struct timeval pcap_timestamp;
         unsigned long rtt_us; /* round-trip time in microseconds */
/*
 * We can't pass a pointer to pcap_header->ts directly to timeval_diff
 * because it's not guaranteed to have the same size as a struct timeval.
 * E.g. OpenBSD 5.1 on amd64.
 */
         pcap_timestamp.tv_sec = pcap_header->ts.tv_sec;
         pcap_timestamp.tv_usec = pcap_header->ts.tv_usec;
         timeval_diff(&pcap_timestamp, &(he->last_send_time), &rtt);
         rtt_us = rtt.tv_sec * 1000000 + rtt.tv_usec;
         cp=msg;
         msg=make_message("%s\tRTT=%lu.%03lu ms", cp, rtt_us/1000, rtt_us%1000);
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
 *	pcap_handle	Pcap handle
 *	he		Host entry to send to. If NULL, then no packet is sent
 *	last_packet_time	Time when last packet was sent
 *
 *      Returns:
 *
 *      The size of the packet that was sent.
 *
 *      This constructs an appropriate packet and sends it to the host
 *      identified by "he" using the socket "s". It also updates the
 *	"last_send_time" field for the host entry.
 *
 *	If we are using the undocumented --writepkttofile option, then we
 *	write the packet to the write_pkt_to_file file descriptor instead of
 *	transmitting it on the network.
 *
 *	If we are using the undocumented --readpktfromfile option, then we
 *	don't send anything.
 */
int
send_packet(pcap_t *pcap_handle, host_entry *he,
            struct timeval *last_packet_time) {
   unsigned char buf[MAX_FRAME];
   size_t buflen;
   ether_hdr frame_hdr;
   arp_ether_ipv4 arpei;
   int nsent = 0;
   unsigned i;
   struct timeval to;
   int n;
/*
 *	Construct Ethernet frame header
 */
   memcpy(frame_hdr.dest_addr, target_mac, ETH_ALEN);
   memcpy(frame_hdr.src_addr, source_mac, ETH_ALEN);
   frame_hdr.frame_type = htons(eth_pro);
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
   if (arp_spa_is_tpa) {
      if (he) {
         arpei.ar_sip = he->addr.s_addr;
      }
   } else {
      arpei.ar_sip = arp_spa;
   }
   if (he)
      arpei.ar_tip = he->addr.s_addr;
/*
 *	Copy the required data into the output buffer "buf" and set "buflen"
 *	to the number of bytes in this buffer.
 */
   marshal_arp_pkt(buf, &frame_hdr, &arpei, &buflen, padding, padding_len);
/*
 *	If host entry pointer is NULL, just return with the packet length.
 */
   if (he == NULL)
      return buflen;
/*
 *	Check that the host is live. Complain if not.
 */
   if (!he->live) {
      warn_msg("***\tsend_packet called on non-live host: SHOULDN'T HAPPEN");
      return 0;
   }
/*
 *	Update the last send times for this host.
 */
   Gettimeofday(last_packet_time);
   he->last_send_time.tv_sec  = last_packet_time->tv_sec;
   he->last_send_time.tv_usec = last_packet_time->tv_usec;
   he->num_sent++;
/*
 *	If we are using the undocumented --readpktfromfile option, don't send
 *	anything and just return with the number of bytes we would have sent.
 */
   if (pkt_read_file_flag) {
      return buflen;
   }
/*
 *	Send the packet.
 */
   if (verbose > 1)
      warn_msg("---\tSending packet #%u to host %s tmo %d", he->num_sent,
               my_ntoa(he->addr), he->timeout);
   if (write_pkt_to_file) {	/* Writing to file */
      nsent = write(write_pkt_to_file, buf, buflen);
   } else {			/* Send packet to Ethernet adaptor */
      to.tv_sec  = retry_send_interval/1000000;
      to.tv_usec = (retry_send_interval - 1000000*to.tv_sec);
      for (i=0; i<retry_send; i++) {
          nsent = pcap_sendpacket(pcap_handle, buf, buflen);
          if (nsent >= 0) {	/* Successfully sent packet */
              break;
          } else if (errno != EAGAIN) {	/* Unrecoverable error */
              err_sys("ERROR: failed to send packet");
          }
          if (retry_send_interval > 0) {
              if (verbose)
                 warn_msg("---\tRetrying send after %d microsecond delay (#%d of %d)",
                          retry_send_interval, i, retry_send);
              n = select(0, NULL, NULL, NULL, &to); /* Delay */
              if (n < 0) {
                 err_sys("select");
              }
          }
      }
   }
   if (nsent < 0)
      err_sys("ERROR: failed to send packet");

   return buflen;
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
 *      This is called once after all hosts have been processed. It can be
 *      used to perform any tidying-up or statistics-displaying required.
 *      It does not have to do anything.
 */
void
clean_up(pcap_t *pcap_handle) {
   struct pcap_stat stats;

   if (!plain_flag) {
      if (pcap_handle && !pkt_read_file_flag) {
         if ((pcap_stats(pcap_handle, &stats)) < 0)
            err_msg("pcap_stats: %s", pcap_geterr(pcap_handle));

         printf("%u packets received by filter, %u packets dropped by kernel\n",
                stats.ps_recv, stats.ps_drop);
      }
   }
   if (pcap_dump_handle) {
      pcap_dump_close(pcap_dump_handle);
   }
   if (pcap_handle) {
      pcap_close(pcap_handle);
   }
}

/*
 *	usage -- display usage message and exit
 *
 *	Inputs:
 *
 *	status		Status code to pass to exit()
 *	detailed	zero for brief output, non-zero for detailed output
 *
 *	Returns:
 *
 *	None (this function never returns).
 */
void
usage(int status, int detailed) {
   fprintf(stdout, "Usage: arp-scan [options] [hosts...]\n");
   fprintf(stdout, "\n");
   fprintf(stdout, "Target hosts must be specified on the command line unless the --file option is\n");
   fprintf(stdout, "given, in which case the targets are read from the specified file instead, or\n");
   fprintf(stdout, "the --localnet option is used, in which case the targets are generated from\n");
   fprintf(stdout, "the network interface IP address and netmask.\n");
   fprintf(stdout, "\n");
   fprintf(stdout, "You will need to be root, or arp-scan must be SUID root, in order to run\n");
   fprintf(stdout, "arp-scan, because the functions that it uses to read and write packets\n");
   fprintf(stdout, "require root privilege.\n");
   fprintf(stdout, "\n");
   fprintf(stdout, "The target hosts can be specified as IP addresses or hostnames. You can also\n");
   fprintf(stdout, "specify the target as IPnetwork/bits (e.g. 192.168.1.0/24) to specify all hosts\n");
   fprintf(stdout, "in the given network (network and broadcast addresses included), or\n");
   fprintf(stdout, "IPstart-IPend (e.g. 192.168.1.3-192.168.1.27) to specify all hosts in the\n");
   fprintf(stdout, "inclusive range, or IPnetwork:NetMask (e.g. 192.168.1.0:255.255.255.0) to\n");
   fprintf(stdout, "specify all hosts in the given network and mask.\n");
   fprintf(stdout, "\n");
   fprintf(stdout, "These different options for specifying target hosts may be used both on the\n");
   fprintf(stdout, "command line, and also in the file specified with the --file option.\n");
   fprintf(stdout, "\n");
   if (detailed) {
      fprintf(stdout, "Options:\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "Note: where an option takes a value, that value is specified as a letter in\n");
      fprintf(stdout, "angle brackets. The letter indicates the type of data that is expected:\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<s> A character string, e.g. --file=hostlist.txt.\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<i> An integer, which can be specified as a decimal number or as a hexadecimal\n");
      fprintf(stdout, "    number if preceded with 0x, e.g. --arppro=2048 or --arpro=0x0800.\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<f> A floating point decimal number, e.g. --backoff=1.5.\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<m> An Ethernet MAC address, which can be specified either in the format\n");
      fprintf(stdout, "    01:23:45:67:89:ab, or as 01-23-45-67-89-ab. The alphabetic hex characters\n");
      fprintf(stdout, "    may be either upper or lower case. E.g. --arpsha=01:23:45:67:89:ab.\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<a> An IPv4 address, e.g. --arpspa=10.0.0.1\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<h> Binary data specified as a hexadecimal string, which should not\n");
      fprintf(stdout, "    include a leading 0x. The alphabetic hex characters may be either\n");
      fprintf(stdout, "    upper or lower case. E.g. --padding=aaaaaaaaaaaa\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<x> Something else. See the description of the option for details.\n");
      fprintf(stdout, "\n--help or -h\t\tDisplay this usage message and exit.\n");
      fprintf(stdout, "\n--file=<s> or -f <s>\tRead hostnames or addresses from the specified file\n");
      fprintf(stdout, "\t\t\tinstead of from the command line. One name or IP\n");
      fprintf(stdout, "\t\t\taddress per line. Use \"-\" for standard input.\n");
      fprintf(stdout, "\n--localnet or -l\tGenerate addresses from network interface configuration.\n");
      fprintf(stdout, "\t\t\tUse the network interface IP address and network mask\n");
      fprintf(stdout, "\t\t\tto generate the list of target host addresses.\n");
      fprintf(stdout, "\t\t\tThe list will include the network and broadcast\n");
      fprintf(stdout, "\t\t\taddresses, so an interface address of 10.0.0.1 with\n");
      fprintf(stdout, "\t\t\tnetmask 255.255.255.0 would generate 256 target\n");
      fprintf(stdout, "\t\t\thosts from 10.0.0.0 to 10.0.0.255 inclusive.\n");
      fprintf(stdout, "\t\t\tIf you use this option, you cannot specify the --file\n");
      fprintf(stdout, "\t\t\toption or specify any target hosts on the command line.\n");
      fprintf(stdout, "\t\t\tThe interface specifications are taken from the\n");
      fprintf(stdout, "\t\t\tinterface that arp-scan will use, which can be\n");
      fprintf(stdout, "\t\t\tchanged with the --interface option.\n");
      fprintf(stdout, "\n--retry=<i> or -r <i>\tSet total number of attempts per host to <i>,\n");
      fprintf(stdout, "\t\t\tdefault=%d.\n", DEFAULT_RETRY);
      fprintf(stdout, "\n--retry-send=<i> or -Y <i> Set total number of send packet attempts to <i>,\n");
      fprintf(stdout, "\t\t\tdefault=%d.\n", DEFAULT_RETRY_SEND);
      fprintf(stdout, "\n--retry-send-interval=<i> or -E <i> Set interval between send packet attempts to <i>.\n");
      fprintf(stdout, "\t\t\tThe interval specified is in milliseconds by default.\n");
      fprintf(stdout, "\t\t\tor in microseconds if \"u\" is appended to the value.\n");
      fprintf(stdout, "\t\t\tdefault=%d.\n", DEFAULT_RETRY_SEND_INTERVAL/1000);
      fprintf(stdout, "\n--timeout=<i> or -t <i>\tSet initial per host timeout to <i> ms, default=%d.\n", DEFAULT_TIMEOUT);
      fprintf(stdout, "\t\t\tThis timeout is for the first packet sent to each host.\n");
      fprintf(stdout, "\t\t\tsubsequent timeouts are multiplied by the backoff\n");
      fprintf(stdout, "\t\t\tfactor which is set with --backoff.\n");
      fprintf(stdout, "\n--interval=<x> or -i <x> Set minimum packet interval to <x>.\n");
      fprintf(stdout, "\t\t\tThis controls the outgoing bandwidth usage by limiting\n");
      fprintf(stdout, "\t\t\tthe rate at which packets can be sent. The packet\n");
      fprintf(stdout, "\t\t\tinterval will be no smaller than this number.\n");
      fprintf(stdout, "\t\t\tIf you want to use up to a given bandwidth, then it is\n");
      fprintf(stdout, "\t\t\teasier to use the --bandwidth option instead.\n");
      fprintf(stdout, "\t\t\tThe interval specified is in milliseconds by default,\n");
      fprintf(stdout, "\t\t\tor in microseconds if \"u\" is appended to the value.\n");
      fprintf(stdout, "\n--bandwidth=<x> or -B <x> Set desired outbound bandwidth to <x>, default=%d.\n", DEFAULT_BANDWIDTH);
      fprintf(stdout, "\t\t\tThe value is in bits per second by default. If you\n");
      fprintf(stdout, "\t\t\tappend \"K\" to the value, then the units are kilobits\n");
      fprintf(stdout, "\t\t\tper sec; and if you append \"M\" to the value, the\n");
      fprintf(stdout, "\t\t\tunits are megabits per second.\n");
      fprintf(stdout, "\t\t\tThe \"K\" and \"M\" suffixes represent the decimal, not\n");
      fprintf(stdout, "\t\t\tbinary, multiples. So 64K is 64000, not 65536.\n");
      fprintf(stdout, "\t\t\tYou cannot specify both --interval and --bandwidth\n");
      fprintf(stdout, "\t\t\tbecause they are just different ways to change the\n");
      fprintf(stdout, "\t\t\tsame underlying parameter.\n");
      fprintf(stdout, "\n--backoff=<f> or -b <f>\tSet timeout backoff factor to <f>, default=%.2f.\n", DEFAULT_BACKOFF_FACTOR);
      fprintf(stdout, "\t\t\tThe per-host timeout is multiplied by this factor\n");
      fprintf(stdout, "\t\t\tafter each timeout. So, if the number of retries\n");
      fprintf(stdout, "\t\t\tis 3, the initial per-host timeout is 500ms and the\n");
      fprintf(stdout, "\t\t\tbackoff factor is 1.5, then the first timeout will be\n");
      fprintf(stdout, "\t\t\t500ms, the second 750ms and the third 1125ms.\n");
      fprintf(stdout, "\n--verbose or -v\t\tDisplay verbose progress messages.\n");
      fprintf(stdout, "\t\t\tUse more than once for greater effect:\n");
      fprintf(stdout, "\t\t\t1 - Display the network address and mask used when the\n");
      fprintf(stdout, "\t\t\t    --localnet option is specified, display any\n");
      fprintf(stdout, "\t\t\t    nonzero packet padding, display packets received\n");
      fprintf(stdout, "\t\t\t    from unknown hosts, and show when each pass through\n");
      fprintf(stdout, "\t\t\t    the list completes.\n");
      fprintf(stdout, "\t\t\t2 - Show each packet sent and received, when entries\n");
      fprintf(stdout, "\t\t\t    are removed from the list, the pcap filter string,\n");
      fprintf(stdout, "\t\t\t    and counts of MAC/Vendor mapping entries.\n");
      fprintf(stdout, "\t\t\t3 - Display the host list before scanning starts.\n");
      fprintf(stdout, "\n--version or -V\t\tDisplay program version and exit.\n");
      fprintf(stdout, "\n--random or -R\t\tRandomise the host list.\n");
      fprintf(stdout, "\t\t\tThis option randomises the order of the hosts in the\n");
      fprintf(stdout, "\t\t\thost list, so the ARP packets are sent to the hosts in\n");
      fprintf(stdout, "\t\t\ta random order. It uses the Knuth shuffle algorithm.\n");
      fprintf(stdout, "\n--randomseed=<i>\tUse <i> to seed the pseudo random number generator.\n");
      fprintf(stdout, "\t\t\tThis option seeds the PRNG with the specified number,\n");
      fprintf(stdout, "\t\t\twhich can be useful if you want to ensure that the\n");
      fprintf(stdout, "\t\t\trandom host list is reproducible. By default, the PRNG\n");
      fprintf(stdout, "\t\t\tis seeded with an unpredictable value. This option is\n");
      fprintf(stdout, "\t\t\tonly effective in conjunction with the --random (-R)\n");
      fprintf(stdout, "\t\t\toption.\n");
      fprintf(stdout, "\n--numeric or -N\t\tIP addresses only, no hostnames.\n");
      fprintf(stdout, "\t\t\tWith this option, all hosts must be specified as\n");
      fprintf(stdout, "\t\t\tIP addresses. Hostnames are not permitted. No DNS\n");
      fprintf(stdout, "\t\t\tlookups will be performed.\n");
      fprintf(stdout, "\n--snap=<i> or -n <i>\tSet the pcap snap length to <i>. Default=%d.\n", SNAPLEN);
      fprintf(stdout, "\t\t\tThis specifies the frame capture length. This\n");
      fprintf(stdout, "\t\t\tlength includes the data-link header.\n");
      fprintf(stdout, "\t\t\tThe default is normally sufficient.\n");
      fprintf(stdout, "\n--interface=<s> or -I <s> Use network interface <s>.\n");
      fprintf(stdout, "\t\t\tIf this option is not specified, arp-scan will search\n");
      fprintf(stdout, "\t\t\tthe system interface list for the lowest numbered,\n");
      fprintf(stdout, "\t\t\tconfigured up interface (excluding loopback).\n");
      fprintf(stdout, "\t\t\tThe interface specified must support ARP.\n");
      fprintf(stdout, "\n--quiet or -q\t\tOnly display minimal output. No protocol decoding.\n");
      fprintf(stdout, "\t\t\tIf this option is specified, then only the IP address\n");
      fprintf(stdout, "\t\t\tand MAC address are displayed for each responding host.\n");
      fprintf(stdout, "\t\t\tNo protocol decoding is performed and the OUI mapping\n");
      fprintf(stdout, "\t\t\tfiles are not used.\n");
      fprintf(stdout, "\n--plain or -x\t\tDisplay plain output showing only responding hosts.\n");
      fprintf(stdout, "\t\t\tThis option suppresses the printing of the header and\n");
      fprintf(stdout, "\t\t\tfooter text, and only displays one line for each\n");
      fprintf(stdout, "\t\t\tresponding host. Useful if the output will be\n");
      fprintf(stdout, "\t\t\tparsed by a script.\n");
      fprintf(stdout, "\n--ignoredups or -g\tDon't display duplicate packets.\n");
      fprintf(stdout, "\t\t\tBy default, duplicate packets are displayed and are\n");
      fprintf(stdout, "\t\t\tflagged with \"(DUP: n)\".\n");
      fprintf(stdout, "\n--ouifile=<s> or -O <s>\tUse IEEE Ethernet OUI to vendor mapping file <s>.\n");
      fprintf(stdout, "\t\t\tIf this option is not specified, the default filename\n");
      fprintf(stdout, "\t\t\tis %s in the current directory. If that is\n", OUIFILENAME);
      fprintf(stdout, "\t\t\tnot found, then the file\n");
      fprintf(stdout, "\t\t\t%s/%s is used.\n", DATADIR, OUIFILENAME);
      fprintf(stdout, "\n--iabfile=<s> or -O <s>\tUse IEEE Ethernet IAB to vendor mapping file <s>.\n");
      fprintf(stdout, "\t\t\tIf this option is not specified, the default filename\n");
      fprintf(stdout, "\t\t\tis %s in the current directory. If that is\n", IABFILENAME);
      fprintf(stdout, "\t\t\tnot found, then the file\n");
      fprintf(stdout, "\t\t\t%s/%s is used.\n", DATADIR, IABFILENAME);
      fprintf(stdout, "\n--macfile=<s> or -O <s>\tUse custom Ethernet MAC to vendor mapping file <s>.\n");
      fprintf(stdout, "\t\t\tIf this option is not specified, the default filename\n");
      fprintf(stdout, "\t\t\tis %s in the current directory. If that is\n", MACFILENAME);
      fprintf(stdout, "\t\t\tnot found, then the file\n");
      fprintf(stdout, "\t\t\t%s/%s is used.\n", DATADIR, MACFILENAME);
      fprintf(stdout, "\n--srcaddr=<m> or -S <m> Set the source Ethernet MAC address to <m>.\n");
      fprintf(stdout, "\t\t\tThis sets the 48-bit hardware address in the Ethernet\n");
      fprintf(stdout, "\t\t\tframe header for outgoing ARP packets. It does not\n");
      fprintf(stdout, "\t\t\tchange the hardware address in the ARP packet, see\n");
      fprintf(stdout, "\t\t\t--arpsha for details on how to change that address.\n");
      fprintf(stdout, "\t\t\tThe default is the Ethernet address of the outgoing\n");
      fprintf(stdout, "\t\t\tinterface.\n");
      fprintf(stdout, "\n--destaddr=<m> or -T <m> Send the packets to Ethernet MAC address <m>\n");
      fprintf(stdout, "\t\t\tThis sets the 48-bit destination address in the\n");
      fprintf(stdout, "\t\t\tEthernet frame header.\n");
      fprintf(stdout, "\t\t\tThe default is the broadcast address ff:ff:ff:ff:ff:ff.\n");
      fprintf(stdout, "\t\t\tMost operating systems will also respond if the ARP\n");
      fprintf(stdout, "\t\t\trequest is sent to their MAC address, or to a\n");
      fprintf(stdout, "\t\t\tmulticast address that they are listening on.\n");
      fprintf(stdout, "\n--arpsha=<m> or -u <m>\tUse <m> as the ARP source Ethernet address\n");
      fprintf(stdout, "\t\t\tThis sets the 48-bit ar$sha field in the ARP packet\n");
      fprintf(stdout, "\t\t\tIt does not change the hardware address in the frame\n");
      fprintf(stdout, "\t\t\theader, see --srcaddr for details on how to change\n");
      fprintf(stdout, "\t\t\tthat address. The default is the Ethernet address of\n");
      fprintf(stdout, "\t\t\tthe outgoing interface.\n");
      fprintf(stdout, "\n--arptha=<m> or -w <m>\tUse <m> as the ARP target Ethernet address\n");
      fprintf(stdout, "\t\t\tThis sets the 48-bit ar$tha field in the ARP packet\n");
      fprintf(stdout, "\t\t\tThe default is zero, because this field is not used\n");
      fprintf(stdout, "\t\t\tfor ARP request packets.\n");
      fprintf(stdout, "\n--prototype=<i> or -y <i> Set the Ethernet protocol type to <i>, default=0x%.4x.\n", DEFAULT_ETH_PRO);
      fprintf(stdout, "\t\t\tThis sets the 16-bit protocol type field in the\n");
      fprintf(stdout, "\t\t\tEthernet frame header.\n");
      fprintf(stdout, "\t\t\tSetting this to a non-default value will result in the\n");
      fprintf(stdout, "\t\t\tpacket being ignored by the target, or sent to the\n");
      fprintf(stdout, "\t\t\twrong protocol stack.\n");
      fprintf(stdout, "\n--arphrd=<i> or -H <i>\tUse <i> for the ARP hardware type, default=%d.\n", DEFAULT_ARP_HRD);
      fprintf(stdout, "\t\t\tThis sets the 16-bit ar$hrd field in the ARP packet.\n");
      fprintf(stdout, "\t\t\tThe normal value is 1 (ARPHRD_ETHER). Most, but not\n");
      fprintf(stdout, "\t\t\tall, operating systems will also respond to 6\n");
      fprintf(stdout, "\t\t\t(ARPHRD_IEEE802). A few systems respond to any value.\n");
      fprintf(stdout, "\n--arppro=<i> or -p <i>\tUse <i> for the ARP protocol type, default=0x%.4x.\n", DEFAULT_ARP_PRO);
      fprintf(stdout, "\t\t\tThis sets the 16-bit ar$pro field in the ARP packet.\n");
      fprintf(stdout, "\t\t\tMost operating systems only respond to 0x0800 (IPv4)\n");
      fprintf(stdout, "\t\t\tbut some will respond to other values as well.\n");
      fprintf(stdout, "\n--arphln=<i> or -a <i>\tSet the hardware address length to <i>, default=%d.\n", DEFAULT_ARP_HLN);
      fprintf(stdout, "\t\t\tThis sets the 8-bit ar$hln field in the ARP packet.\n");
      fprintf(stdout, "\t\t\tIt sets the claimed length of the hardware address\n");
      fprintf(stdout, "\t\t\tin the ARP packet. Setting it to any value other than\n");
      fprintf(stdout, "\t\t\tthe default will make the packet non RFC compliant.\n");
      fprintf(stdout, "\t\t\tSome operating systems may still respond to it though.\n");
      fprintf(stdout, "\t\t\tNote that the actual lengths of the ar$sha and ar$tha\n");
      fprintf(stdout, "\t\t\tfields in the ARP packet are not changed by this\n");
      fprintf(stdout, "\t\t\toption; it only changes the ar$hln field.\n");
      fprintf(stdout, "\n--arppln=<i> or -P <i>\tSet the protocol address length to <i>, default=%d.\n", DEFAULT_ARP_PLN);
      fprintf(stdout, "\t\t\tThis sets the 8-bit ar$pln field in the ARP packet.\n");
      fprintf(stdout, "\t\t\tIt sets the claimed length of the protocol address\n");
      fprintf(stdout, "\t\t\tin the ARP packet. Setting it to any value other than\n");
      fprintf(stdout, "\t\t\tthe default will make the packet non RFC compliant.\n");
      fprintf(stdout, "\t\t\tSome operating systems may still respond to it though.\n");
      fprintf(stdout, "\t\t\tNote that the actual lengths of the ar$spa and ar$tpa\n");
      fprintf(stdout, "\t\t\tfields in the ARP packet are not changed by this\n");
      fprintf(stdout, "\t\t\toption; it only changes the ar$pln field.\n");
      fprintf(stdout, "\n--arpop=<i> or -o <i>\tUse <i> for the ARP operation, default=%d.\n", DEFAULT_ARP_OP);
      fprintf(stdout, "\t\t\tThis sets the 16-bit ar$op field in the ARP packet.\n");
      fprintf(stdout, "\t\t\tMost operating systems will only respond to the value 1\n");
      fprintf(stdout, "\t\t\t(ARPOP_REQUEST). However, some systems will respond\n");
      fprintf(stdout, "\t\t\tto other values as well.\n");
      fprintf(stdout, "\n--arpspa=<a> or -s <a>\tUse <a> as the source IP address.\n");
      fprintf(stdout, "\t\t\tThe address should be specified in dotted quad format;\n");
      fprintf(stdout, "\t\t\tor the literal string \"dest\", which sets the source\n");
      fprintf(stdout, "\t\t\taddress to be the same as the target host address.\n");
      fprintf(stdout, "\t\t\tThis sets the 32-bit ar$spa field in the ARP packet.\n");
      fprintf(stdout, "\t\t\tSome operating systems check this, and will only\n");
      fprintf(stdout, "\t\t\trespond if the source address is within the network\n");
      fprintf(stdout, "\t\t\tof the receiving interface. Others don't care, and\n");
      fprintf(stdout, "\t\t\twill respond to any source address.\n");
      fprintf(stdout, "\t\t\tBy default, the outgoing interface address is used.\n");
      fprintf(stdout, "\n\t\t\tWARNING: Setting ar$spa to the destination IP address\n");
      fprintf(stdout, "\t\t\tcan disrupt some operating systems, as they assume\n");
      fprintf(stdout, "\t\t\tthere is an IP address clash if they receive an ARP\n");
      fprintf(stdout, "\t\t\trequest for their own address.\n");
      fprintf(stdout, "\n--padding=<h> or -A <h>\tSpecify padding after packet data.\n");
      fprintf(stdout, "\t\t\tSet the padding data to hex value <h>. This data is\n");
      fprintf(stdout, "\t\t\tappended to the end of the ARP packet, after the data.\n");
      fprintf(stdout, "\t\t\tMost, if not all, operating systems will ignore any\n");
      fprintf(stdout, "\t\t\tpadding. The default is no padding, although the\n");
      fprintf(stdout, "\t\t\tEthernet driver on the sending system may pad the\n");
      fprintf(stdout, "\t\t\tpacket to the minimum Ethernet frame length.\n");
      fprintf(stdout, "\n--llc or -L\t\tUse RFC 1042 LLC framing with SNAP.\n");
      fprintf(stdout, "\t\t\tThis option causes the outgoing ARP packets to use\n");
      fprintf(stdout, "\t\t\tIEEE 802.2 framing with a SNAP header as described\n");
      fprintf(stdout, "\t\t\tin RFC 1042. The default is to use Ethernet-II\n");
      fprintf(stdout, "\t\t\tframing.\n");
      fprintf(stdout, "\t\t\tarp-scan will decode and display received ARP packets\n");
      fprintf(stdout, "\t\t\tin either Ethernet-II or IEEE 802.2 formats\n");
      fprintf(stdout, "\t\t\tirrespective of this option.\n");
      fprintf(stdout, "\n--vlan=<i> or -Q <i>\tUse 802.1Q tagging with VLAN id <i>.\n");
      fprintf(stdout, "\t\t\tThis option causes the outgoing ARP packets to use\n");
      fprintf(stdout, "\t\t\t802.1Q VLAN tagging with a VLAN ID of <i>, which should\n");
      fprintf(stdout, "\t\t\tbe in the range 0 to 4095 inclusive.\n");
      fprintf(stdout, "\t\t\tarp-scan will always decode and display received ARP\n");
      fprintf(stdout, "\t\t\tpackets in 802.1Q format irrespective of this option.\n");
      fprintf(stdout, "\n--pcapsavefile=<s> or -W <s>\tWrite received packets to pcap savefile <s>.\n");
      fprintf(stdout, "\t\t\tThis option causes received ARP responses to be written\n");
      fprintf(stdout, "\t\t\tto the specified pcap savefile as well as being decoded\n");
      fprintf(stdout, "\t\t\tand displayed. This savefile can be analysed with\n");
      fprintf(stdout, "\t\t\tprograms that understand the pcap file format, such as\n");
      fprintf(stdout, "\t\t\t\"tcpdump\" and \"wireshark\".\n");
      fprintf(stdout, "\n--rtt or -D\t\tDisplay the packet round-trip time.\n");
   } else {
      fprintf(stdout, "use \"arp-scan --help\" for detailed information on the available options.\n");
   }
   fprintf(stdout, "\n");
   fprintf(stdout, "Report bugs or send suggestions at %s\n", PACKAGE_BUGREPORT);
   fprintf(stdout, "See the arp-scan homepage at https://github.com/royhills/arp-scan\n");
   exit(status);
}

/*
 *      add_host_pattern -- Add one or more new hosts to the list.
 *
 *      Inputs:
 *
 *      pattern = The host pattern to add.
 *      host_timeout = Per-host timeout in ms.
 *
 *      Returns: None
 *
 *      This adds one or more new hosts to the list. The pattern argument
 *      can either be a single host or IP address, in which case one host
 *      will be added to the list, or it can specify a number of hosts with
 *      the IPnet/bits or IPstart-IPend formats.
 *
 *      The host_timeout and num_hosts arguments are passed unchanged to
 *	add_host().
 */
void
add_host_pattern(const char *pattern, unsigned host_timeout) {
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
 *	Compile regex patterns if this is the first time we've been called.
 */
   if (first_call) {
      int result;

      first_call = 0;
      if ((result=regcomp(&iprange_pat, iprange_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         regerror(result, &iprange_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 iprange_pat_str, errbuf);
      }
      if ((result=regcomp(&ipslash_pat, ipslash_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         regerror(result, &ipslash_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 ipslash_pat_str, errbuf);
      }
      if ((result=regcomp(&ipmask_pat, ipmask_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         regerror(result, &ipmask_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 ipmask_pat_str, errbuf);
      }
   }
/*
 *	Make a copy of pattern because we don't want to modify our argument.
 */
   patcopy = dupstr(pattern);

   if (!(regexec(&ipslash_pat, patcopy, 0, NULL, 0))) { /* IPnet/bits */
/*
 *	Get IPnet and bits as integers. Perform basic error checking.
 */
      cp=strchr(patcopy, '/');
      *(cp++)='\0';	/* patcopy points to IPnet, cp points to bits */
      if (!(inet_aton(patcopy, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", patcopy);
      ipnet_val=ntohl(in_val.s_addr);	/* We need host byte order */
      numbits=Strtoul(cp, 10);
      if (numbits<3 || numbits>32)
         err_msg("ERROR: Number of bits in %s must be between 3 and 32",
                 pattern);
/*
 *	Construct 32-bit network bitmask from number of bits.
 */
      mask=0;
      for (i=0; i<numbits; i++)
         mask += 1 << i;
      mask = mask << (32-i);
/*
 *	Mask off the network. Warn if the host bits were non-zero.
 */
      network=ipnet_val & mask;
      if (network != ipnet_val)
         warn_msg("WARNING: host part of %s is non-zero", pattern);
/*
 *	Determine maximum and minimum host values. We include the host
 *	and broadcast.
 */
      hoststart=0;
      hostend=(1<<(32-numbits))-1;
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
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
         snprintf(ipstr, sizeof(ipstr), "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, host_timeout, 1);
      }
   } else if (!(regexec(&ipmask_pat, patcopy, 0, NULL, 0))) { /* IPnet:netmask */
/*
 *	Get IPnet and bits as integers. Perform basic error checking.
 */
      cp=strchr(patcopy, ':');
      *(cp++)='\0';	/* patcopy points to IPnet, cp points to netmask */
      if (!(inet_aton(patcopy, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", patcopy);
      ipnet_val=ntohl(in_val.s_addr);	/* We need host byte order */
      if (!(inet_aton(cp, &mask_val)))
         err_msg("ERROR: %s is not a valid netmask", patcopy);
      mask=ntohl(mask_val.s_addr);	/* We need host byte order */
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
 *	Mask off the network. Warn if the host bits were non-zero.
 */
      network=ipnet_val & mask;
      if (network != ipnet_val)
         warn_msg("WARNING: host part of %s is non-zero", pattern);
/*
 *	Determine maximum and minimum host values. We include the host
 *	and broadcast.
 */
      hoststart=0;
      hostend=(1<<(32-numbits))-1;
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
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
         snprintf(ipstr, sizeof(ipstr), "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, host_timeout, 1);
      }
   } else if (!(regexec(&iprange_pat, patcopy, 0, NULL, 0))) { /* IPstart-IPend */
/*
 *	Get IPstart and IPend as integers.
 */
      cp=strchr(patcopy, '-');
      *(cp++)='\0';	/* patcopy points to IPstart, cp points to IPend */
      if (!(inet_aton(patcopy, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", patcopy);
      hoststart=ntohl(in_val.s_addr);	/* We need host byte order */
      if (!(inet_aton(cp, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", cp);
      hostend=ntohl(in_val.s_addr);	/* We need host byte order */
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
 */
      for (i=hoststart; i<=hostend; i++) {
         int b1, b2, b3, b4;
         char ipstr[16];

         b1 = (i & 0xff000000) >> 24;
         b2 = (i & 0x00ff0000) >> 16;
         b3 = (i & 0x0000ff00) >> 8;
         b4 = (i & 0x000000ff);
         snprintf(ipstr, sizeof(ipstr), "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, host_timeout, 1);
      }
   } else {	/* Single host or IP address */
      add_host(patcopy, host_timeout, numeric_flag);
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
 *	numeric_only = 1 if the host name is definitely an IP address in
 *	               dotted quad format, or 0 if it may be a hostname or
 *	               IP address.
 *
 *	Returns:
 *
 *	None.
 *
 *	This function is called before the helistptr array is created, so
 *	we use the helist array directly.
 */
void
add_host(const char *host_name, unsigned host_timeout, int numeric_only) {
   struct in_addr *hp=NULL;
   struct in_addr addr;
   host_entry *he;
   static int num_left=0;	/* Number of free entries left */
   int result;
   char *ga_err_msg;

   if (numeric_only) {
      result = inet_pton(AF_INET, host_name, &addr);
      if (result < 0) {
         err_sys("ERROR: inet_pton failed for %s", host_name);
      } else if (result == 0) {
         warn_msg("WARNING: \"%s\" is not a valid IPv4 address - target ignored", host_name);
         return;
      }
   } else {
      hp = get_host_address(host_name, AF_INET, &addr, &ga_err_msg);
      if (hp == NULL) {
         warn_msg("WARNING: get_host_address failed for \"%s\": %s - target ignored",
                  host_name, ga_err_msg);
         return;
      }
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

   memcpy(&(he->addr), &addr, sizeof(struct in_addr));
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
 *	Returns:
 *
 *	None.
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
   } else {
      if (verbose > 1)
         warn_msg("***\tremove_host called on non-live host: SHOULDN'T HAPPEN");
   }
}

/*
 *	advance_cursor -- Advance the cursor to point at next live entry
 *
 *	Inputs:
 *
 *	None.
 *
 *	Returns:
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
}

/*
 *	find_host	-- Find a host in the list
 *
 *	Inputs:
 *
 *	he 	Pointer to the current position in the list. Search runs
 *		backwards starting from this point.
 *	addr 	The source IP address that the packet came from.
 *
 *	Returns a pointer to the host entry associated with the specified IP
 *	or NULL if no match found.
 *
 *	This routine finds the host by IP address by comparing "addr" against
 *	"he->addr" for each entry in the list.
 */
host_entry *
find_host(host_entry **he, struct in_addr *addr) {
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
 *	Try to match against our host list.
 */
   p = he;

   do {
      iterations++;
      if ((*p)->addr.s_addr == addr->s_addr) {
         found = 1;
      } else {
         if (p == helistptr) {
            p = helistptr + (num_hosts-1);	/* Wrap round to end */
         } else {
            p--;
         }
      }
   } while (!found && p != he);


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
 *	sock_fd		= Socket file descriptor.
 *	tmo		= Select timeout in us.
 *	pcap_handle 	= pcap handle
 *
 *	Returns:
 *
 *	None.
 *
 *	If the socket file descriptor is -1, this indicates that we are
 *	reading packets from a pcap file and there is no associated network
 *	device.
 */
void
recvfrom_wto(int sock_fd, int tmo, pcap_t *pcap_handle) {
   fd_set readset;
   struct timeval to;
   int n;

   FD_ZERO(&readset);
   if (sock_fd >= 0)
      FD_SET(sock_fd, &readset);
   to.tv_sec  = tmo/1000000;
   to.tv_usec = (tmo - 1000000*to.tv_sec);
   n = select(sock_fd+1, &readset, NULL, NULL, &to);
   if (n < 0) {
      err_sys("select");
   } else if (n == 0 && sock_fd >= 0) {
      return;	/* Timeout */
   }
/*
 * Call pcap_dispatch() to process the packet if we are reading packets.
 */
   if (pcap_handle) {
      if ((pcap_dispatch(pcap_handle, -1, callback, NULL)) == -1)
         err_sys("pcap_dispatch: %s\n", pcap_geterr(pcap_handle));
   }
}

/*
 *	dump_list -- Display contents of host list for debugging
 *
 *	Inputs:
 *
 *	None.
 *
 *	Returns:
 *
 *	None.
 */
void
dump_list(void) {
   unsigned i;

   printf("Host List:\n\n");
   printf("Entry\tIP Address\n");
   for (i=0; i<num_hosts; i++)
      printf("%u\t%s\n", i+1, my_ntoa(helistptr[i]->addr));
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
callback(u_char *args ATTRIBUTE_UNUSED,
         const struct pcap_pkthdr *header, const u_char *packet_in) {
   arp_ether_ipv4 arpei;
   ether_hdr frame_hdr;
   int n = header->caplen;
   struct in_addr source_ip;
   host_entry *temp_cursor;
   unsigned char extra_data[MAX_FRAME];
   size_t extra_data_len;
   int vlan_id;
   int framing;
/*
 *      Check that the packet is large enough to decode.
 */
   if (n < ETHER_HDR_SIZE + ARP_PKT_SIZE) {
      printf("%d byte packet too short to decode\n", n);
      return;
   }
/*
 *	Limit packet size to the maximum Ethernet frame size we expect
 *	to avoid potential buffer overruns later.
 */
   if (n > MAX_FRAME) {
      n = MAX_FRAME;
   }
/*
 *	Unmarshal packet buffer into structures and determine framing type
 */
   framing = unmarshal_arp_pkt(packet_in, n, &frame_hdr, &arpei, extra_data,
                               &extra_data_len, &vlan_id);
/*
 *	Determine source IP address.
 */
   source_ip.s_addr = arpei.ar_sip;
/*
 *	We've received a response. Try to match up the packet by IP address
 *
 *	We should really start searching at the host before the cursor, as we
 *	know that the host to match cannot be the one at the cursor position
 *	because we call advance_cursor() after sending each packet. However,
 *	the time saved is minimal, and it's not worth the extra complexity.
 */
   temp_cursor=find_host(cursor, &source_ip);
   if (temp_cursor) {
/*
 *	We found an IP match for the packet.
 */
/*
 *	Display the packet and increment the number of responders if
 *	the entry is "live" or we are not ignoring duplicates.
 */
      temp_cursor->num_recv++;
      if (verbose > 1)
         warn_msg("---\tReceived packet #%u from %s",
                  temp_cursor->num_recv ,my_ntoa(source_ip));
      if ((temp_cursor->live || !ignore_dups)) {
         if (pcap_dump_handle) {
            pcap_dump((unsigned char *)pcap_dump_handle, header, packet_in);
         }
         display_packet(temp_cursor, &arpei, extra_data, extra_data_len,
                        framing, vlan_id, &frame_hdr, header);
         responders++;
      }
      if (verbose > 1)
         warn_msg("---\tRemoving host %s - Received %d bytes",
                  my_ntoa(source_ip), n);
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
      {"retry-send", required_argument, 0, 'Y'},
      {"retry-send-interval", required_argument, 0, 'E'},
      {"timeout", required_argument, 0, 't'},
      {"interval", required_argument, 0, 'i'},
      {"backoff", required_argument, 0, 'b'},
      {"verbose", no_argument, 0, 'v'},
      {"version", no_argument, 0, 'V'},
      {"snap", required_argument, 0, 'n'},
      {"interface", required_argument, 0, 'I'},
      {"quiet", no_argument, 0, 'q'},
      {"ignoredups", no_argument, 0, 'g'},
      {"random", no_argument, 0, 'R'},
      {"numeric", no_argument, 0, 'N'},
      {"bandwidth", required_argument, 0, 'B'},
      {"ouifile", required_argument, 0, 'O'},
      {"iabfile", required_argument, 0, 'F'},
      {"macfile", required_argument, 0, 'm'},
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
      {"srcaddr", required_argument, 0, 'S'},
      {"localnet", no_argument, 0, 'l'},
      {"llc", no_argument, 0, 'L'},
      {"vlan", required_argument, 0, 'Q'},
      {"pcapsavefile", required_argument, 0, 'W'},
      {"writepkttofile", required_argument, 0, OPT_WRITEPKTTOFILE},
      {"readpktfromfile", required_argument, 0, OPT_READPKTFROMFILE},
      {"rtt", no_argument, 0, 'D'},
      {"plain", no_argument, 0, 'x'},
      {"randomseed", required_argument, 0, OPT_RANDOMSEED},
      {0, 0, 0, 0}
   };
/*
 * available short option characters:
 *
 * lower:       --cde----jk--------------z
 * UPPER:       --C---G--JK-M-------U--X-Z
 * Digits:      0123456789
 */
   const char *short_options =
      "f:hr:Y:E:t:i:b:vVn:I:qgRNB:O:s:o:H:p:T:P:a:A:y:u:w:S:F:m:lLQ:W:Dx";
   int arg;
   int options_index=0;

   while ((arg=getopt_long_only(argc, argv, short_options, long_options, &options_index)) != -1) {
      switch (arg) {
         struct in_addr source_ip_address;
         int result;

         case 'f':	/* --file */
            strlcpy(filename, optarg, sizeof(filename));
            filename_flag=1;
            break;
         case 'h':	/* --help */
            usage(EXIT_SUCCESS, 1);
            break;	/* NOTREACHED */
         case 'r':	/* --retry */
            retry=Strtoul(optarg, 10);
            break;
         case 'Y':	/* --retry-send */
            retry_send=Strtoul(optarg, 10);
            break;
         case 'E':	/* --retry-send-interval */
            retry_send_interval=str_to_interval(optarg);
            break;
         case 't':	/* --timeout */
            timeout=Strtoul(optarg, 10);
            break;
         case 'i':	/* --interval */
            interval=str_to_interval(optarg);
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
            break;	/* NOTREACHED */
         case 'n':	/* --snap */
            snaplen=Strtol(optarg, 0);
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
         case 'B':      /* --bandwidth */
            bandwidth=str_to_bandwidth(optarg);
            break;
         case 'O':	/* --ouifile */
            strlcpy(ouifilename, optarg, sizeof(ouifilename));
            break;
         case 'F':	/* --iabfile */
            strlcpy(iabfilename, optarg, sizeof(iabfilename));
            break;
         case 'm':	/* --macfile */
            strlcpy(macfilename, optarg, sizeof(macfilename));
            break;
         case 's':	/* --arpspa */
            arp_spa_flag = 1;
            if ((strcmp(optarg,"dest")) == 0) {
               arp_spa_is_tpa = 1;
            } else {
               if ((inet_pton(AF_INET, optarg, &source_ip_address)) <= 0)
                  err_sys("inet_pton failed for %s", optarg);
               memcpy(&arp_spa, &(source_ip_address.s_addr), sizeof(arp_spa));
            }
            break;
         case 'o':	/* --arpop */
            arp_op=Strtol(optarg, 0);
            break;
         case 'H':	/* --arphrd */
            arp_hrd=Strtol(optarg, 0);
            break;
         case 'p':	/* --arppro */
            arp_pro=Strtol(optarg, 0);
            break;
         case 'T':	/* --destaddr */
            result = get_ether_addr(optarg, target_mac);
            if (result != 0)
               err_msg("Invalid target MAC address: %s", optarg);
            break;
         case 'P':	/* --arppln */
            arp_pln=Strtol(optarg, 0);
            break;
         case 'a':	/* --arphln */
            arp_hln=Strtol(optarg, 0);
            break;
         case 'A':	/* --padding */
            if (strlen(optarg) % 2)     /* Length is odd */
               err_msg("ERROR: Length of --padding argument must be even (multiple of 2).");
            padding=hex2data(optarg, &padding_len);
            break;
         case 'y':	/* --prototype */
            eth_pro=Strtol(optarg, 0);
            break;
         case 'u':	/* --arpsha */
            result = get_ether_addr(optarg, arp_sha);
            if (result != 0)
               err_msg("Invalid source MAC address: %s", optarg);
            arp_sha_flag = 1;
            break;
         case 'w':	/* --arptha */
            result = get_ether_addr(optarg, arp_tha);
            if (result != 0)
               err_msg("Invalid target MAC address: %s", optarg);
            break;
         case 'S':	/* --srcaddr */
            result = get_ether_addr(optarg, source_mac);
            if (result != 0)
               err_msg("Invalid target MAC address: %s", optarg);
            source_mac_flag = 1;
            break;
         case 'l':	/* --localnet */
            localnet_flag = 1;
            break;
         case 'L':	/* --llc */
            llc_flag = 1;
            break;
         case 'Q':	/* --vlan */
            ieee_8021q_vlan = Strtol(optarg, 0);
            break;
         case 'W':	/* --pcapsavefile */
            strlcpy(pcap_savefile, optarg, sizeof(pcap_savefile));
            break;
         case OPT_WRITEPKTTOFILE: /* --writepkttofile */
            strlcpy(pkt_filename, optarg, sizeof(pkt_filename));
            pkt_write_file_flag=1;
            break;
         case OPT_READPKTFROMFILE: /* --readpktfromfile */
            strlcpy(pkt_filename, optarg, sizeof(pkt_filename));
            pkt_read_file_flag=1;
            break;
         case 'D':	/* --rtt */
            rtt_flag = 1;
            break;
         case 'x':	/* --plain */
            plain_flag = 1;
            break;
         case OPT_RANDOMSEED: /* --randomseed */
            random_seed=Strtoul(optarg, 0);
            break;
         default:	/* Unknown option */
            usage(EXIT_FAILURE, 0);
            break;	/* NOTREACHED */
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
 *	Returns:
 *
 *	None.
 *
 *	This displays the arp-scan version information.
 */
void
arp_scan_version (void) {
   fprintf(stdout, "%s\n\n", PACKAGE_STRING);
   fprintf(stdout, "Copyright (C) 2005-2019 Roy Hills\n");
   fprintf(stdout, "arp-scan comes with NO WARRANTY to the extent permitted by law.\n");
   fprintf(stdout, "You may redistribute copies of arp-scan under the terms of the GNU\n");
   fprintf(stdout, "General Public License.\n");
   fprintf(stdout, "For more information about these matters, see the file named COPYING.\n");
   fprintf(stdout, "\n");
   fprintf(stdout, "%s\n", pcap_lib_version());
}

/*
 *	get_host_address -- Obtain target host IP address
 *
 *	Inputs:
 *
 *	name		The name to lookup
 *	af		The address family
 *	addr		Pointer to the IP address buffer
 *	error_msg	The error message, or NULL if no problem.
 *
 *	Returns:
 *
 *	Pointer to the IP address, or NULL if an error occurred.
 *
 *	This function is basically a wrapper for getaddrinfo().
 */
struct in_addr *
get_host_address(const char *name, int af, struct in_addr *addr,
                 char **error_msg) {
   static char err[MAXLINE];
   static struct in_addr ipa;

   struct addrinfo *res;
   struct addrinfo hints;
   struct sockaddr_in sa_in;
   int result;

   if (addr == NULL)	/* Use static storage if no buffer specified */
      addr = &ipa;

   memset(&hints, '\0', sizeof(hints));
   if (af == AF_INET) {
      hints.ai_family = AF_INET;
   } else {
      err_msg("get_host_address: unknown address family: %d", af);
   }

   result = getaddrinfo(name, NULL, &hints, &res);
   if (result != 0) {	/* Error occurred */
      snprintf(err, MAXLINE, "%s", gai_strerror(result));
      *error_msg = err;
      return NULL;
   }

   memcpy(&sa_in, res->ai_addr, sizeof(sa_in));
   memcpy(addr, &sa_in.sin_addr, sizeof(struct in_addr));

   freeaddrinfo(res);

   *error_msg = NULL;
   return addr;
}

/*
 *	my_ntoa -- IPv6 compatible inet_ntoa replacement
 *
 *	Inputs:
 *
 *	addr	The IP address
 *
 *	Returns:
 *
 *	Pointer to the string representation of the IP address.
 *
 *	This currently only supports IPv4.
 */
const char *
my_ntoa(struct in_addr addr) {
   static char ip_str[MAXLINE];
   const char *cp;

   cp = inet_ntop(AF_INET, &addr, ip_str, MAXLINE);

   return cp;
}

/*
 *	marshal_arp_pkt -- Marshal ARP packet from struct to buffer
 *
 *	Inputs:
 *
 *	buffer		Pointer to the output buffer
 *	frame_hdr	The Ethernet frame header
 *	arp_pkt		The ARP packet
 *	buf_siz		The size of the output buffer
 *	frame_padding	Any padding to add after the ARP payload.
 *	frame_padding_len	The length of the padding.
 *
 *	Returns:
 *
 *	None
 */
void
marshal_arp_pkt(unsigned char *buffer, ether_hdr *frame_hdr,
                arp_ether_ipv4 *arp_pkt, size_t *buf_siz,
                const unsigned char *frame_padding, size_t frame_padding_len) {
   unsigned char llc_snap[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00};
   unsigned char vlan_tag[] = {0x81, 0x00, 0x00, 0x00};
   unsigned char *cp;
   size_t packet_size;

   cp = buffer;
/*
 *	Set initial packet length to the size of an Ethernet frame using
 *	Ethernet-II format plus the size of the ARP data. This may be
 *	increased later by LLC/SNAP frame format or padding after the
 *	ARP data.
 */
   packet_size = sizeof(frame_hdr->dest_addr) + sizeof(frame_hdr->src_addr) +
                 sizeof(frame_hdr->frame_type) +
                 sizeof(arp_pkt->ar_hrd) + sizeof(arp_pkt->ar_pro) +
                 sizeof(arp_pkt->ar_hln) + sizeof(arp_pkt->ar_pln) +
                 sizeof(arp_pkt->ar_op)  + sizeof(arp_pkt->ar_sha) +
                 sizeof(arp_pkt->ar_sip) + sizeof(arp_pkt->ar_tha) +
                 sizeof(arp_pkt->ar_tip);
/*
 *	Copy the Ethernet frame header to the buffer.
 */
   memcpy(cp, &(frame_hdr->dest_addr), sizeof(frame_hdr->dest_addr));
   cp += sizeof(frame_hdr->dest_addr);
   memcpy(cp, &(frame_hdr->src_addr), sizeof(frame_hdr->src_addr));
   cp += sizeof(frame_hdr->src_addr);
/*
 *	Add 802.1Q tag if we are using VLAN tagging
 */
   if (ieee_8021q_vlan != -1) {
      uint16_t tci;

      tci = htons(ieee_8021q_vlan);
      memcpy(cp, vlan_tag, sizeof(vlan_tag));
      memcpy(cp+2, &tci, sizeof(tci));
      cp += sizeof(vlan_tag);
      packet_size += sizeof(vlan_tag);
   }
   if (llc_flag) {	/* With 802.2 LLC framing, type field is frame size */
      uint16_t frame_size;

      frame_size=htons(packet_size + sizeof(llc_snap));
      memcpy(cp, &(frame_size), sizeof(frame_size));
   } else {		/* Normal Ethernet-II framing */
      memcpy(cp, &(frame_hdr->frame_type), sizeof(frame_hdr->frame_type));
   }
   cp += sizeof(frame_hdr->frame_type);
/*
 *	Add IEEE 802.2 LLC and SNAP fields if we are using LLC frame format.
 */
   if (llc_flag) {
      memcpy(cp, llc_snap, sizeof(llc_snap));
      memcpy(cp+6, &(frame_hdr->frame_type), sizeof(frame_hdr->frame_type));
      cp += sizeof(llc_snap);
      packet_size += sizeof(llc_snap);
   }
/*
 *	Add the ARP data.
 */
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
   cp += sizeof(arp_pkt->ar_tip);
/*
 *	Add padding if specified
 */
   if (frame_padding != NULL) {
      size_t safe_padding_len;

      safe_padding_len = frame_padding_len;
      if (packet_size + frame_padding_len > MAX_FRAME) {
         safe_padding_len = MAX_FRAME - packet_size;
      }
      memcpy(cp, frame_padding, safe_padding_len);
      cp += safe_padding_len;
      packet_size += safe_padding_len;
   }
   *buf_siz = packet_size;
}

/*
 *	unmarshal_arp_pkt -- Un Marshal ARP packet from buffer to struct
 *
 *	Inputs:
 *
 *	buffer		Pointer to the input buffer
 *	buf_len		Length of input buffer
 *	frame_hdr	The ethernet frame header
 *	arp_pkt		The arp packet data
 *	extra_data	Any extra data after the ARP data (typically padding)
 *	extra_data_len	Length of extra data
 *	vlan_id		802.1Q VLAN identifier
 *
 *	Returns:
 *
 *	An integer representing the data link framing:
 *	0 = Ethernet-II
 *	1 = 802.3 with LLC/SNAP
 *
 *	extra_data and extra_data_len are only calculated and returned if
 *	extra_data is not NULL.
 *
 *	vlan_id is set to -1 if the packet does not use 802.1Q tagging.
 */
int
unmarshal_arp_pkt(const unsigned char *buffer, size_t buf_len,
                  ether_hdr *frame_hdr, arp_ether_ipv4 *arp_pkt,
                  unsigned char *extra_data, size_t *extra_data_len,
                  int *vlan_id) {
   const unsigned char *cp;
   int framing=FRAMING_ETHERNET_II;

   cp = buffer;
/*
 *	Extract the Ethernet frame header data
 */
   memcpy(&(frame_hdr->dest_addr), cp, sizeof(frame_hdr->dest_addr));
   cp += sizeof(frame_hdr->dest_addr);
   memcpy(&(frame_hdr->src_addr), cp, sizeof(frame_hdr->src_addr));
   cp += sizeof(frame_hdr->src_addr);
/*
 *	Check for 802.1Q VLAN tagging, indicated by a type code of
 *	0x8100 (TPID).
 */
   if (*cp == 0x81 && *(cp+1) == 0x00) {
      uint16_t tci;
      cp += 2;	/* Skip TPID */
      memcpy(&tci, cp, sizeof(tci));
      cp += 2;	/* Skip TCI */
      *vlan_id = ntohs(tci);
      *vlan_id &= 0x0fff;	/* Mask off PRI and CFI */
   } else {
      *vlan_id = -1;
   }
   memcpy(&(frame_hdr->frame_type), cp, sizeof(frame_hdr->frame_type));
   cp += sizeof(frame_hdr->frame_type);
/*
 *	Check for an LLC header with SNAP. If this is present, the 802.2 LLC
 *	header will contain DSAP=0xAA, SSAP=0xAA, Control=0x03.
 *	If this 802.2 LLC header is present, skip it and the SNAP header
 */
   if (*cp == 0xAA && *(cp+1) == 0xAA && *(cp+2) == 0x03) {
      cp += 8;	/* Skip eight bytes */
      framing = FRAMING_LLC_SNAP;
   }
/*
 *	Extract the ARP packet data
 */
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
   cp += sizeof(arp_pkt->ar_tip);

   if (extra_data != NULL) {
      int length;

/*
 * buf_len will not exceed MAX_FRAME
 */
      length = buf_len - (cp - buffer);
      if (length > 0) {		/* Extra data after ARP packet */
         memcpy(extra_data, cp, length);
      }
      *extra_data_len = length;
   }

   return framing;
}

/*
 *	add_mac_vendor -- Add MAC/Vendor mappings to the hash table
 *
 *	Inputs:
 *
 *	map_filename	The name of the file containing the mappings
 *
 *	Returns:
 *
 *	The number of entries added to the hash table.
 */
int
add_mac_vendor(const char *map_filename) {
   static int first_call=1;
   FILE *fp;	/* MAC/Vendor file handle */
   static const char *oui_pat_str = "([^\t]+)\t[\t ]*([^\t\r\n]+)";
   static regex_t oui_pat;
   regmatch_t pmatch[3];
   size_t key_len;
   size_t data_len;
   char *key;
   char *data;
   char line[MAXLINE];
   int line_count;
   int result;
   ENTRY hash_entry;
/*
 *	Compile the regex pattern if this is the first time we
 *	have been called.
 */
   if (first_call) {
      first_call=0;
      if ((result=regcomp(&oui_pat, oui_pat_str, REG_EXTENDED))) {
         char reg_errbuf[MAXLINE];
         regerror(result, &oui_pat, reg_errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 oui_pat_str, reg_errbuf);
      }
   }
/*
 *	Open the file.
 */
   if ((fp = fopen(map_filename, "r")) == NULL) {
      warn_sys("WARNING: Cannot open MAC/Vendor file %s", map_filename);
      return 0;
   }
   line_count=0;
/*
 *
 */
   while (fgets(line, MAXLINE, fp)) {
      if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
         continue;	/* Skip blank lines and comments */
      result = regexec(&oui_pat, line, 3, pmatch, 0);
      if (result == REG_NOMATCH || pmatch[1].rm_so < 0 || pmatch[2].rm_so < 0) {
         warn_msg("WARNING: Could not parse oui: %s", line);
      } else if (result != 0) {
         char reg_errbuf[MAXLINE];
         regerror(result, &oui_pat, reg_errbuf, MAXLINE);
         err_msg("ERROR: oui regexec failed: %s", reg_errbuf);
      } else {
         key_len = pmatch[1].rm_eo - pmatch[1].rm_so;
         data_len = pmatch[2].rm_eo - pmatch[2].rm_so;
         key=Malloc(key_len+1);
         data=Malloc(data_len+1);
/*
 * We cannot use strlcpy because the source is not guaranteed to be null
 * terminated. Therefore we use strncpy, specifying one less than the total
 * length, and manually null terminate the destination.
 */
         strncpy(key, line+pmatch[1].rm_so, key_len);
         key[key_len] = '\0';
         strncpy(data, line+pmatch[2].rm_so, data_len);
         data[data_len] = '\0';
         hash_entry.key = key;
         hash_entry.data = data;
         if ((hsearch(hash_entry, ENTER)) == NULL) {
            warn_msg("hsearch([%s, %s], ENTER)", key, data);
         } else {
            line_count++;
         }
      }
   }
   fclose(fp);
   return line_count;
}

/*
 *	get_mac_vendor_filename -- Determine MAC/Vendor mapping filename
 *
 *	Inputs:
 *
 *	specified_filename	The filename specified on the command line
 *	default_datadir		The default data directory
 *	default_filename	The default filename
 *
 *	Returns:
 *
 *	The MAC/Vendor mapping filename.
 *
 *	If a filename was specified as an option on the command line, then
 *	that filename is used. Otherwise we look for the default filename
 *	in the current directory, and use that if it's present. Otherwise
 *	we use the default filename in the default directory.
 *
 */
char *
get_mac_vendor_filename(const char *specified_filename,
                        const char *default_datadir,
                        const char *default_filename) {
   struct stat statbuf;
   int status;
   char *file_name;

   if (*specified_filename == '\0') {	/* No filename specified */
      file_name = make_message("%s", default_filename);
      status = stat(file_name, &statbuf);
      if (status == -1 && errno == ENOENT) {
         free(file_name);
         file_name = make_message("%s/%s", default_datadir, default_filename);
      }
   } else {	/* Filename specified */
      file_name = make_message("%s", specified_filename);
   }
   return file_name;
}

/*
 *      get_source_ip   -- Get IP address associated with given interface
 *
 *      Inputs:
 *
 *      interface_name  The name of the network interface
 *      ip_addr         (output) The IP Address associated with the device
 *
 *      Returns:
 *
 *      Zero on success, or -1 on failure.
 */
int
get_source_ip(const char *interface_name, struct in_addr *ip_addr) {
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_if_t *alldevsp;
   pcap_if_t *device;
   pcap_addr_t *addr;
   struct sockaddr *sa;
   struct sockaddr_in *sin = NULL;

   if ((pcap_findalldevs(&alldevsp, errbuf)) != 0) {
      printf("pcap_findalldevs: %s\n", errbuf);
   }

   device=alldevsp;
   while (device != NULL && (strcmp(device->name,interface_name) != 0)) {
      device=device->next;
   }
   if (device != NULL) { /* We found a device name match */
      for (addr=device->addresses; addr != NULL; addr=addr->next) {
         sa = addr->addr;
         if (sa->sa_family == AF_INET) {
            sin = (struct sockaddr_in *) sa;
            break;
         }
      }
      if (sin == NULL) {
         memset(&(ip_addr->s_addr), '\0', sizeof(ip_addr->s_addr));
         pcap_freealldevs(alldevsp);
         return -1;
      }

      memcpy(ip_addr, &(sin->sin_addr), sizeof(*ip_addr));

      pcap_freealldevs(alldevsp);

      return 0;
   } else {
/* If we reach here then we have not found the interface name in the list
 * supplied by pcap_findalldevs() so try getifaddrs() instead if available.
 * This happens for legacy Linux alias interfaces with names like eth0:0.
 * Ref: https://github.com/royhills/arp-scan/issues/3
 */
#ifdef HAVE_GETIFADDRS
      struct ifaddrs *ifap, *ifa;

      if ((getifaddrs(&ifap)) != 0) {
         err_sys("getifaddrs");
      }
      for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
         if (ifa->ifa_addr && ifa->ifa_addr->sa_family==AF_INET &&
             strcmp(ifa->ifa_name,interface_name) == 0) {
            sin = (struct sockaddr_in *) ifa->ifa_addr;
            memcpy(ip_addr, &(sin->sin_addr), sizeof(*ip_addr));
            return 0;
         }
      }
      freeifaddrs(ifap);
#endif
   }
/* If we reach here then we haven't found an IP address */
   return -1;
}
