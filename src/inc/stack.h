#ifndef _SRC_STACK_H
#define _SRC_STACK_H

#include "parser.h"


namespace ants {

void stack_in(pkt_parser *p, pcap_t* handle, const struct pcap_pkthdr* header, const u_char* pkt_data);

void stack_out(pkt_parser *p, pcap_t* handle, const struct pcap_pkthdr* header, const u_char* pkt_data);

}

#endif