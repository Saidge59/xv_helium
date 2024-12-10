#ifndef FRAG_SCENARIO_SUPPORT_H
#define FRAG_SCENARIO_SUPPORT_H

#include <helium.h>
#include <stdio.h>
#include "bllist.h"

typedef struct test_packet {
  int length;
  uint8_t bytes[];
} test_packet;

DYNAMIC_ARRAY(packet_list, test_packet*, sizeof(test_packet*));
typedef struct packet_list packet_list;

typedef struct frag_scenario {
  char* name;
  int he_frag_size;
  test_packet* original_pkt;
  int num_frag_packets;
  packet_list* frag_packets;
} frag_scenario;

DYNAMIC_ARRAY(scenario_list, frag_scenario*, sizeof(frag_scenario*));
typedef struct scenario_list scenario_list;

void create_scenario(scenario_list* to_populate, char* name, int he_frag_size,
                     test_packet* original_pkt, int num_frag_packets, ...);
void free_scenario(frag_scenario* scenario);

#endif
