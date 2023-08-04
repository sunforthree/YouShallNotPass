#include "inc/driver.h"

namespace ants {

// error buffer define.
char errBuf[PCAP_ERRBUF_SIZE];
int err;

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

void packet_handler(u_char* parser, const struct pcap_pkthdr* header, const u_char* pkt_data) {  
  u_int len = header->len;
  if (len < sizeof(struct ether_header)) {
    fprintf(stderr, "incomplated packet\n");
    return;
  }

  struct pkt_parser* internal_parser = (struct pkt_parser*)parser;
  parse_packet(internal_parser, header, pkt_data);

  /* Get back parser. */
  parser = (u_char*)internal_parser;
  /* Function show will print pkt info by layers. */
  show(internal_parser);
}

}