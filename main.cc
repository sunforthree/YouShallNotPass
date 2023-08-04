#include "src/inc/driver.h"
#include "pthread.h"

using namespace ants;

struct main_args
{
  pcap_t *handle;
  pkt_parser *parser;
  pcap_handler handler;
};

static void *process_packet_wrapper(void *args)
{
  main_args *a = reinterpret_cast<main_args *>(args);
  process_packet(a->handle, a->parser, a->handler);
  return NULL;
}

int main(int argc, char** argv)
{
  /* we need two interfaces to run this program:
   * One to communicate with the printer, the other for the outer world
   */
  /* TODO: encapsulate this process to reduce code duplication */
  std::string inbound = "ens3f0";
  std::string outbound = "ens3f1";
  pcap_t* handle_in;
  pcap_t* handle_out;

  struct pkt_parser* parser_in;
  struct pkt_parser* parser_out;

  handle_in = init_pcap(ONLINE_TYPE, inbound.c_str());
  handle_out = init_pcap(ONLINE_TYPE, outbound.c_str());
  parser_in = init_parser();
  parser_out = init_parser();

  pthread_t tidx_in, tidx_out;
  main_args marg_in = {.handle = handle_in, .parser = parser_in, .handler = packet_handler_in};
  main_args marg_out = {.handle = handle_out, .parser = parser_out, .handler = packet_handler_out};

  if(pthread_create(&tidx_in, NULL, process_packet_wrapper, (void *)&marg_in)) {
    fprintf(stderr, "Cannot create thread for inbound traffic\n");
    exit(-errno);
  }
  
  if(pthread_create(&tidx_out, NULL, process_packet_wrapper, (void *)&marg_out)) {
    fprintf(stderr, "Cannot create thread for outbound traffic\n");
    exit(-errno);
  }

  /* Wait, otherwise `main` will return */
  pthread_join(tidx_in, NULL);
  pthread_join(tidx_out, NULL);

  end_pcap(handle_in);
  end_pcap(handle_out);
  end_parser(parser_in);
  end_parser(parser_out);

  return 0;
}