#include "frag_scenario_support.h"

#include <stdarg.h>

void create_scenario(scenario_list* to_populate, char* name, int he_frag_size,
                     test_packet* original_pkt, int num_frag_packets, ...) {
  frag_scenario* new_scenario = jecalloc(1, sizeof(frag_scenario));
  new_scenario->frag_packets = jecalloc(1, sizeof(packet_list));
  packet_list_init(new_scenario->frag_packets);

  new_scenario->name = name;
  new_scenario->he_frag_size = he_frag_size;
  new_scenario->original_pkt = original_pkt;
  new_scenario->num_frag_packets = num_frag_packets;

  va_list argp;
  va_start(argp, num_frag_packets);
  test_packet* cur_packet;
  for(int i = 0; i < num_frag_packets; i++) {
    cur_packet = va_arg(argp, test_packet*);
    packet_list_push(new_scenario->frag_packets, cur_packet);
  }

  scenario_list_push(to_populate, new_scenario);
}

void free_scenario(frag_scenario* scenario) {
  packet_list_free(scenario->frag_packets);
  jefree(scenario->frag_packets);
  jefree(scenario);
}
