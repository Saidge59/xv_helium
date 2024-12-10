#ifndef HE_SHARED_INSIDE_FLOW_H
#define HE_SHARED_INSIDE_FLOW_H

#include <helium.h>

// This module encapsulates logic shared between the HPT and TUN Gateways

void he_inside_process_packet(he_server_t *state, uint8_t *msg_content, int length);
void he_inside_lookup_conn(he_server_t *state, uint8_t *msg_content, int length);

#endif  // HE_FLOW_OUT_H
