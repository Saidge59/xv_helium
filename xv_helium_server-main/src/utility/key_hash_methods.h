#ifndef _KEY_HASH_METHODS_H
#define _KEY_HASH_METHODS_H
#include <stdint.h>
#include <stddef.h>

/**
 * structure holds IPv4 IP and port combo
 */
typedef struct he_v4_ip_port {
  uint32_t ip;
  uint16_t port;
} he_v4_ip_port_t;

/**
 * Comparison function for ordering & comparison (hash).
 * IPv4 IP and port combinations.
 */
int compare_v4_ip_port(he_v4_ip_port_t left, he_v4_ip_port_t right);

/**
 * Hash an IPv4 IP and port combo. Internally just sums
 * the 32bit IP and port into a 48 bit value.
 */
size_t v4_ip_port_hash(he_v4_ip_port_t m);

/**
 * Compare IPv4 ip addresses for ordering and comparison (hash).
 */
int compare_ipv4(uint32_t m, uint32_t r);

/**
 * Hash an ipv4 IP address for hashmaps (identity function).
 */
size_t ipv4_hash(uint32_t m);

/**
 * Compare session identifiers (hash).
 */
int compare_session_id(uint64_t l, uint64_t r);

/**
 * Hash a session identifier (identity function).
 */
size_t session_id_hash(uint64_t m);

#endif
