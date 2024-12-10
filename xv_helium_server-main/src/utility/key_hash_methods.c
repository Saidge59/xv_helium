#include "key_hash_methods.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

int compare_v4_ip_port(he_v4_ip_port_t left, he_v4_ip_port_t right) {
  int retval = compare_ipv4(left.ip, right.ip);
  if(retval != 0) {
    return retval;
  }
  return compare_ipv4(left.port, right.port);
}

size_t v4_ip_port_hash(he_v4_ip_port_t m) {
  uint64_t ip = m.ip;
  uint64_t port = m.port;
  uint64_t combo = (ip << 16) | port;
  return combo;
}

int compare_ipv4(uint32_t m, uint32_t r) {
  if(m == r) {
    return 0;
  } else if(m < r) {
    return -1;
  } else {
    return 1;
  }
}

size_t ipv4_hash(uint32_t m) {
  return (size_t)ntohl(m);
}

int compare_session_id(uint64_t l, uint64_t r) {
  if(l == r) {
    return 0;
  } else if(l < r) {
    return -1;
  } else {
    return 1;
  }
}

size_t session_id_hash(uint64_t m) {
  return (size_t)m;
}
