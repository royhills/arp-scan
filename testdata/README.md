# testdata directory
This directory contains data files used by `make check` to run self tests.

| Filename | Description |
| --- | --- |
| pkt-simple-response.pcap | Simple ARP response packet |
| pkt-padding-response.pcap | ARP response followed by non-zero padding |
| pkt-vlan-response.pcap | ARP response with 802.1Q VLAN tag |
| pkt-llc-response.pcap | ARP response with 802.2 LLC/SNAP framing |
| pkt-vlan-llc-response.pcap | ARP response with 802.2 LLC/SNAP framing and 802.1Q VLAN tag |
| pkt-net1921681-response.pcap | 56 ARP responses from 192.168.1.0/24 |
| pkt-trailer-response.pcap | ARP response with RFC 893 trailer encapsulation |
| pkt-dup-response.pcap | ARP responses with duplicate packets |
| pkt-diff-frame-addr.pcap | ARP response with Ethernet source address != ar$sha |
| pkt-local-admin.pcap | ARP response with locally administered source address |
| pkt-ieee-regcheck.pcap | ARP responses with source addresses in IEEE IAB, MA-M, MA-L and MA-S registries |
| pkt-too-short.pcap | Truncated ARP response packet |
| pkt-simple-request.dat | Raw ARP simple request packet |
| pkt-custom-request.dat | Raw custom ARP request packet |
| pkt-custom-request-padding.dat | Raw ARP request followed by non-zero padding |
| pkt-custom-request-llc.dat | Raw ARP request with 802.2 LLC/SNAP framing |
| pkt-custom-request-vlan.dat | Raw ARP request with 802.1Q VLAN tag |
| pkt-custom-request-vlan-llc.dat | Raw ARP request with 802.2 LLC/SNAP framing and 802.1Q VLAN tag |
