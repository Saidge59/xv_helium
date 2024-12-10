#include "ip_rewrite.h"
#include "network.h"

#include <assert.h>

uint32_t he_extract_dst_ip_ipv4(uint8_t *msg_content, size_t length) {
  assert(length >= sizeof(ipv4_header_t));
  return ((ipv4_header_t *)msg_content)->dst_addr;
}

void he_rewrite_ip_from_client_to_tun_ipv4(he_server_connection_t *conn, uint8_t *packet,
                                           size_t length) {
  assert(length >= sizeof(ipv4_header_t));
  ipv4_header_t *ipv4_hdr = (ipv4_header_t *)packet;
  ipv4_hdr->src_addr = conn->inside_ip;
  he_adjust_packet_checksums(packet, length, conn->state->client_ip_u32, conn->inside_ip);
}

void he_rewrite_ip_from_tun_to_client_ipv4(he_server_connection_t *conn, uint8_t *packet,
                                           size_t length) {
  assert(length >= sizeof(ipv4_header_t));
  ipv4_header_t *ipv4_hdr = (ipv4_header_t *)packet;
  ipv4_hdr->dst_addr = conn->state->client_ip_u32;

  he_adjust_packet_checksums(packet, length, conn->inside_ip, conn->state->client_ip_u32);
}
