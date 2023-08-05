/* Printer protocol stack implementation */
#include <pcap.h>
#include <stdint.h>
#include <string.h>

#include "inc/stack.h"
#include "inc/driver.h"

namespace ants {

static char printer_mac[6];

static char pkt_buffer[1500];

enum {
  PRINTER_DHCP_REQUESTED
};

static unsigned status;

void stack_in(pkt_parser *p, pcap_t *handle_out, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
  /* 1. The printer send DHCP, requiring for an IP.
   *    At this time, the source IP is pure zero
   */
  if (p->flags.ip == true
      && p->flags.udp == true
      && p->flags.dhcp == true ) {
        if (p->dhcp->dhcp_op == DHCP_DISCOVER) {
          /* record printer MAC */
          memcpy(printer_mac, p->ether->shost, 6);
          status = PRINTER_DHCP_REQUESTED;
          /* TODO: check in parser if this packet exceed default MTU */
          /* before sending, we need to copy the packet, in order to modify it */
          memcpy(pkt_buffer, (const char *)pkt_data, header->caplen);
          /* send packets from outbound interface */
          memcpy(pkt_buffer, outbound_mac, 6);
          pcap_inject(handle_out, pkt_buffer, header->caplen);
          return;
        }
      }
}

void stack_out(pkt_parser *p, pcap_t *handle_in, const struct pcap_pkthdr* header, const u_char* pkt_data)
{

}

}

