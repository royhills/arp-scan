#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

int main(void) {
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_if_t *alldevs;
   pcap_if_t *device;

   if (pcap_findalldevs(&alldevs, errbuf) == -1) {
      printf("pcap_findalldevs: %s\n", errbuf);
      exit(1);
   }
   device=alldevs;
   while (device != NULL) {
      printf("Name: %s, Flags: %x\n", device->name, device->flags);
      device = device->next;
   } 
   return 0;
}
