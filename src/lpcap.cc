#include "inc/lpcap.h"

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

void packet_process(pcap_t* handle, struct pkt_parser* parser) {
  if (pcap_loop(handle, -1, packet_handler, (u_char*)parser) < 0) {
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
  packet_parse(internal_parser, header, pkt_data);

  /* Get back parser. */
  parser = (u_char*)internal_parser;
  /* Function show will print pkt info by layers. */
  show(internal_parser);
}

void packet_parse(struct pkt_parser* parser, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
  /* Clean parser flags. */
  clean_flags(parser->flags);

  u_int len = header->len;

  /* Get Ethernet header. */
  parser->flags.ether = true;
  struct ether_header* eth_header = (struct ether_header*)pkt_data;
  int ether_header_len = sizeof(struct ether_header);
  strncpy(parser->ether->dhost, mac_ntoa(eth_header->ether_dhost), sizeof(parser->ether->dhost));
  strncpy(parser->ether->shost, mac_ntoa(eth_header->ether_shost), sizeof(parser->ether->shost));
  parser->ether->type = ntohs(eth_header->ether_type);
  /* End of Ethernet header. */

  /* Get ip header. */
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    parser->flags.ip = true;
    struct ip_parser* ip = (struct ip_parser*)(pkt_data + ether_header_len);
    int ip_header_len = IP_HL(ip) << 2;
    len -= ether_header_len;
    if (len < sizeof(struct ip_parser)) {
      fprintf(stderr, "truncated ip %d\n", len);
      return;
    }

    parser->ip = ip;
    /* As struct 'ip' get network byte order, internal_ip need change to host byte order. */
    parser->ip->ip_len = ntohs(ip->ip_len);
    parser->ip->ip_id = ntohs(ip->ip_id);
    parser->ip->ip_off = ntohs(ip->ip_off);
    parser->ip->ip_sum = ntohs(ip->ip_sum);
    /* End of IP header. */

    /* Get tcp header. */
    if (u_char(ip->ip_p) == IPPROTO_TCP) {
      parser->flags.tcp = true;
      struct tcphdr* tcp_header = (struct tcphdr*)(pkt_data + ether_header_len + ip_header_len);
      int tcp_header_len = tcp_header->th_off << 2;
      len -= ip_header_len;

      struct tcp_parser* tcp = parser->tcp;
      tcp->sport = ntohs(tcp_header->th_sport);
      tcp->dport = ntohs(tcp_header->th_dport);
      tcp->seq = ntohl(tcp_header->th_seq);
      tcp->ack = ntohl(tcp_header->th_ack);
      tcp->header_len = tcp_header->th_off << 2;
      tcp->flags = tcp_header->th_flags;
      tcp->windows = ntohs(tcp_header->window);
      tcp->checksum = ntohs(tcp_header->th_sum);
      tcp->urp = ntohs(tcp_header->th_urp);
      /* End of tcp header. */
    }
    /* Get udp header. */
    else if (u_char(ip->ip_p) == IPPROTO_UDP) {
      parser->flags.udp = true;
      struct udphdr* udp_header = (struct udphdr*)(pkt_data + ether_header_len + ip_header_len);


      struct udp_parser* udp = parser->udp;
      udp->sport = ntohs(udp_header->uh_sport);
      udp->dport = ntohs(udp_header->uh_dport);
      udp->len = ntohs(udp_header->len);
      udp->checksum = ntohs(udp_header->check);
      /* End of udp header. */
    }
  }
}
}