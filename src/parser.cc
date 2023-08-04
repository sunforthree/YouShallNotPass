#include "inc/parser.h"

namespace ants {
struct pkt_parser* init_parser() {
  struct pkt_parser* parser;
  
  parser = new struct pkt_parser;
  parser->ether = new struct ether_parser;
  // parser->ip = new struct ip_parser;
  parser->tcp = new struct tcp_parser;
  parser->udp = new struct udp_parser;

  return parser;
}

// Delete memory which maybe malloc.
// (Ehter and IP use the raw ptr of packet.)
void end_parser(struct pkt_parser* parser) {
  if (parser->ether != nullptr)
    delete parser->ether;
  // if (parser->ip != nullptr)
  //   delete parser->ip;
  if (parser != nullptr && parser->tcp != nullptr)
    delete parser->tcp;
  if (parser != nullptr && parser->udp != nullptr)
    delete parser->udp;
  if (parser != nullptr)
    delete parser;
}

void show(struct pkt_parser* parser) {
  if (parser->flags.ether && parser->ether != nullptr) {
    printf("###[ Ethernet ]###\n");
    printf("   dst= %s \n", parser->ether->dhost);
    printf("   src= %s \n", parser->ether->shost);
    printf("   type= 0x%02x \n", parser->ether->type);
  }
  if (parser->flags.ip && parser->ip != nullptr) {
    printf("###[ IP ]###\n");
    printf("   version= %d \n", IP_V(parser->ip));
    printf("   ihl= %d \n", IP_HL(parser->ip) << 2);
    printf("   tos= 0x%02x \n", parser->ip->ip_tos);
    printf("   len= %d \n", parser->ip->ip_len);
    printf("   id= 0x%02x \n", parser->ip->ip_id);
    printf("   flags= %s \n", ip_ftoa(parser->ip->ip_off));
    printf("   off= 0x%02x \n", parser->ip->ip_off & IP_OFFMASK);
    printf("   ttl= %d \n", parser->ip->ip_ttl);
    printf("   proto= %d \n", parser->ip->ip_p);
    printf("   chksum= 0x%02x \n", parser->ip->ip_sum);
    printf("   src= %s \n", ip_ntoa(&(parser->ip->ip_src)));
    printf("   dst= %s \n", ip_ntoa(&(parser->ip->ip_dst)));
  }
  if (parser->flags.tcp && parser->tcp != nullptr) {
    printf("###[ TCP ]###\n");
    printf("   sport= %d \n", parser->tcp->sport);
    printf("   dport= %d \n", parser->tcp->dport);
    printf("   seq= %d \n", parser->tcp->seq);
    printf("   ack= %d \n", parser->tcp->ack);
    printf("   header len= %d \n", parser->tcp->header_len);
    printf("   flags= %s \n", tcp_ftoa(parser->tcp->flags));
    printf("   windows= %d \n", parser->tcp->windows);
    printf("   checksum= 0x%02x \n", parser->tcp->checksum);
    printf("   urp= %d \n", parser->tcp->urp);
  }
  if (parser->flags.udp && parser->udp != nullptr) {
    printf("###[ UDP ]###\n");
    printf("   sport= %d \n", parser->udp->sport);
    printf("   dport= %d \n", parser->udp->dport);
    printf("   len= %d \n", parser->udp->len);
    printf("   checksum= 0x%02x \n", parser->udp->checksum);
  }

  printf("\n");
}

char* mac_ntoa(u_char *d) {
  static char str[MAC_ADDRSTRLEN];

  snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

  return str;
}

char* ip_ftoa(uint16_t flag) {
  /* Pre define flags. */
  static int f[] = { 'R', 'D', 'M' };
#define IP_FLG_MAX (sizeof(f) / sizeof(f[0]))
  /* Pre define buffer. */
  static char str[IP_FLG_MAX + 1];
  uint16_t mask = 1 << 15;

  int i;
  for (i = 0; i < IP_FLG_MAX; ++i) {
    if (mask & flag)
      str[i] = f[i];
    else
      str[i] = '-';
    mask >>= 1;
  }
  str[i] = '\0';

  return str;
}

char* ip_ntoa(void* address) {
  static char str[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, address, str, sizeof(str));

  return str;
}

char* tcp_ftoa(uint8_t flag) {
  /* Pre define flags. */
  static int f[] = {'W', 'E', 'U', 'A', 'P', 'R', 'S', 'F'};
#define TCP_FLG_MAX (sizeof(f) / sizeof(f[0]))
  /* Pre define buffer. */
  static char str[TCP_FLG_MAX + 1];
  uint32_t mask = 1 << 7;

  int i;
  for (i = 0; i < TCP_FLG_MAX; ++i) {
    if (mask & flag)
      str[i] = f[i];
    else
      str[i] = '-';
    mask >>= 1;
  }
  str[i] = '\0';

  return str;
}

void clean_flags(struct proto_flag &flags) {
  flags.ether = false;
  flags.ip = false;
  flags.tcp = false;
  flags.udp = false;
  flags.dhcp = false;
}

void parse_packet(struct pkt_parser* parser, const struct pcap_pkthdr* header, const u_char* pkt_data)
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