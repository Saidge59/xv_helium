#ifndef TCP_PROXY_H
#define TCP_PROXY_H

#include <stdint.h>

typedef struct proxy_hdr_v2 {
  uint8_t sig[12]; /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
  uint8_t ver_cmd; /* protocol version and command */
  uint8_t fam;     /* protocol family and address */
  uint16_t len;    /* number of following bytes part of the header */
} proxy_hdr_v2_t;

typedef union proxy_addr {
  struct { /* for TCP/UDP over IPv4, len = 12 */
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
  } ipv4_addr;
  struct { /* for TCP/UDP over IPv6, len = 36 */
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
  } ipv6_addr;
  struct { /* for AF_UNIX sockets, len = 216 */
    uint8_t src_addr[108];
    uint8_t dst_addr[108];
  } unix_addr;
} proxy_addr_t;

#endif  // TCP_PROXY_H
