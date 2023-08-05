#ifndef _SRC_LPCAP_H_
#define _SRC_LPCAP_H_

#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>

#include "parser.h"

// C++ interface to the libpcap.
// It gives sorts of functions to get & parser packets.
// ----------------------------------------------------

namespace ants {

/* Opened interfaces as global variables, avoiding tentative definition */
extern pcap_t *handle_in, *handle_out;

const char inbound_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}; 
const char outbound_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x00};

enum PcapType {
    OFFLINE_TYPE = 0,
    ONLINE_TYPE,
};

// pkt_info is a struct that contains 
// the length of the packet and the packet data.
struct pkt_info {
  bpf_u_int32 length;
  u_char* pkt_data;
};

// Init a handle, the word `type` determines whether
// word `location` is a file or a device.
// OFFLINE_TYPE -> file
// ONLINE_TYPE  -> deivce  
pcap_t* init_pcap(PcapType type, const char* location);

// If handle not nullptr, close it.
void end_pcap(pcap_t* handle);

/* Packet handler for processing inbound (printer -> program)
 * and outbound (program -> higher level router) traffic
 */
void packet_handler_in(u_char* user_Data, const struct pcap_pkthdr* header, const u_char* pkt_data);
void packet_handler_out(u_char* user_Data, const struct pcap_pkthdr* header, const u_char* pkt_data);

// Main function, process packet here,
// pass a function ptr to it do the real handle things.
// 'pcap_handler' parameter is as follows: 
// (u_char *, const struct pcap_pkthdr *, const u_char *)
void process_packet(pcap_t* handle, struct pkt_parser* parser, pcap_handler handler);

} /* namespace ants */

#endif  // _SRC_LPCAP_H_