#include "src/inc/lpcap.h"

using namespace ants;

int main(int argc, char** argv)
{
  pcap_t* handle;
  std::string interface = "eno1";

  struct pkt_parser* parser;

  handle = init_pcap(ONLINE_TYPE, interface.c_str());
  parser = init_parser();

  process_packet(handle, parser);

  end_pcap(handle);
  end_parser(parser);

  return 0;
}