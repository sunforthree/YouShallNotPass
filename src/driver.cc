#include "inc/driver.h"
#include "inc/stack.h"

namespace ants {

pcap_t *handle_in, *handle_out;

// error buffer define.
static char errBuf[PCAP_ERRBUF_SIZE];
static int err;

pcap_t* init_pcap(PcapType type, const char* location) {
  pcap_t* handle;
  /* Begin of pcap handle init. */
  if (type == ONLINE_TYPE) {
    printf("ONLINE MODE\n");
    handle = pcap_open_live(location, BUFSIZ, 1, 1000, errBuf);
    if (handle == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", location, errBuf);
      return NULL;
    }
  }
  else if (type == OFFLINE_TYPE) {
    printf("OFFLINE MODE\n");
    handle = pcap_open_offline(location, errBuf);
    if (handle == NULL) {
      fprintf(stderr, "Couldn't open file %s: %s\n", location, errBuf);
      return NULL;
    }
  }
  /* End of pcap handle init. */

  return handle;
}

void end_pcap(pcap_t* handle) {  
  if (handle != nullptr)
    pcap_close(handle);
  else {
    fprintf(stderr, "Handle was not init!\n");
    return;
  }
}

void process_packet(pcap_t* handle, struct pkt_parser* parser, pcap_handler handler) {
  if (pcap_loop(handle, -1, handler, (u_char*)parser) < 0) {
    fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
    fprintf(stderr, "pcap_loop() failed: %s, errcode: %d\n", errBuf, err);
    exit(-1);
  }
}

void packet_handler_in(u_char* parser, const struct pcap_pkthdr* header, const u_char* pkt_data) {  
  #ifndef NDEBUG
  printf("Receiving an inbound packet, preparing to parse it:\n");
  #endif

  u_int len = header->len;
  if (len < sizeof(struct ether_header)) {
    /* TODO: consider moving this to syslog */
    fprintf(stderr, "incompleted packet\n");
    return;
  }

  struct pkt_parser* internal_parser = (struct pkt_parser*)parser;
  parse_packet(internal_parser, header, pkt_data);

  /* Get back parser. */
  parser = (u_char*)internal_parser;
  
  /* This is a very tricky step: 
   * We don't want the kernel to route the packet from inbound to outbound --
   * Some of the packets even do not hav IP!
   * So we connect our cables here, allowing the inbound thread to send packets
   * directly from outbound interface, which is directly connected with outer network,
   * and vise versa for outbound interface.
   */
  stack_in(internal_parser, handle_out, header, pkt_data);

  #ifndef NDEBUG
  /* Function show will print pkt info by layers. */
  show(internal_parser);
  #endif
}

void packet_handler_out(u_char* parser, const struct pcap_pkthdr* header, const u_char* pkt_data) {  
  #ifndef NDEBUG
  printf("Receiving an outbound packet, preparing to parse it:\n");
  #endif
  
  u_int len = header->len;
  if (len < sizeof(struct ether_header)) {
    /* TODO: consider moving this to syslog */
    fprintf(stderr, "incompleted packet\n");
    return;
  }

  struct pkt_parser* internal_parser = (struct pkt_parser*)parser;
  parse_packet(internal_parser, header, pkt_data);

  /* Get back parser. */
  parser = (u_char*)internal_parser;
  stack_out(internal_parser, handle_in, header, pkt_data);

  #ifndef NDEBUG
  /* Function show will print pkt info by layers. */
  show(internal_parser);
  #endif
}

}