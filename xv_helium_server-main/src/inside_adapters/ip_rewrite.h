#ifndef HE_IP_REWRITE_H
#define HE_IP_REWRITE_H

#include <helium.h>
/**
 * Helium homogenizes client IP addresses to avoid platform inconsistency.
 * From the clients perspectives, they will all have a fixed IP (assigned by the state).
 * When a packet comes into the server from a client, we rewrite the IP address in the packet to
 * the clients assigned tunnel IP address. When a packet comes in from the tun device we rewrite
 * the packet to the homogenized IP address.
 */
uint32_t he_extract_dst_ip_ipv4(uint8_t *packet, size_t length);
void he_rewrite_ip_from_client_to_tun_ipv4(he_server_connection_t *conn, uint8_t *packet,
                                           size_t length);
void he_rewrite_ip_from_tun_to_client_ipv4(he_server_connection_t *conn, uint8_t *packet,
                                           size_t length);

#endif  // HE_IP_REWRITE_H
