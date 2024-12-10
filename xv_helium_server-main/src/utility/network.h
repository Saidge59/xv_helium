/**
 * @file network.h
 * @brief Convenience functions for network tasks
 */

#ifndef NETWORK_H
#define NETWORK_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/**
 * Packet types the packet info method can infer.
 */
typedef enum he_packet_state {
  HE_BAD_PACKET = 0,
  HE_PACKET_IP4 = 1,
  HE_PACKET_IP6 = 2
} he_packet_state_t;

// Following headers from:
// https://stackoverflow.com/questions/16519846/parse-ip-and-tcp-header-especially-common-tcp-header-optionsof-packets-capture
#pragma pack(1)

#define HE_IP_DONT_FRAGMENT (1 << 14)
#define HE_IP_NO_FRAG_OPTIONS 0
#define HE_IP_FRAGMENTS_TO_FOLLOW (1 << 13)
#define HE_IP_FRAGMENT_OFFSET_MULTIPLIER 8
#define HE_IP_LENGTH_BITMASK 0x0F
typedef struct {
  uint8_t ver_ihl;  // 4 bits version and 4 bits internet header length
  uint8_t tos;
  uint16_t total_length;
  uint16_t id;
  uint16_t flags_fo;  // 3 bits flags and 13 bits fragment-offset
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t src_addr;
  uint32_t dst_addr;
} ipv4_header_t;

#define HE_IP_TCP 0x06
#define HE_IP_UDP 0x11
#define HE_TCP_SYN 0x02
typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t data_offset;  // 4 bits
  uint8_t flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_p;
} tcp_header_t;

#define HE_TCP_OPT_NOP 1
#define HE_TCP_OPT_MSS 2
typedef struct {
  uint8_t kind;
  uint8_t size;
} tcp_option_t;

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
} udp_header_t;

#pragma pack()

// The overhead of an IPv4 header and TCP header such that the MSS value can be set correctly
#define HE_MSS_OVERHEAD (sizeof(ipv4_header_t) + sizeof(tcp_header_t))

/**
 * @brief Find where the packet payload starts inside an IPv4 packet
 * @param header A pointer to the IPv4 header
 * @return The offset into the packet where the payload is found
 */
uint16_t he_ip_header_payload_offset(ipv4_header_t *header);

/**
 * @brief Determine if an IPv4 packet has been fragmented
 * @param header A pointer to the IPv4 header
 * @return Whether the packet is fragmented or not
 */
bool he_is_fragmented(ipv4_header_t *header);

/**
 * @brief Determine whether the packet is a valid type and which type it is
 * @param packet Pointer to the packet data
 * @param length The length of the packet
 * @return HE_BAD_PACKET The packet is not a valid type
 * @return HE_PACKET_IP4 The packet has an IPv4 signature
 * @return HE_PACKET_IP6 The packet has an IPv6 signature
 */
he_packet_state_t he_packet_type(uint8_t *packet, size_t length);

/**
 * Differential 16bit ones complement implementation
 * Borrowed from FreeBSD DifferentialChecksum in sys/netinet/libalias/alias_util.c
 *
 * @brief Calculate a differential checksum for use in IPv4, UDP and TCP headers
 * @param cksum A pointer to the checksum field to be updated
 * @param newp A pointer to the data that has been updated
 * @param oldp A pointer to the original data
 * @param n The number of 16bit values to iterate over
 *
 * This function works by iterating over the changed data, and updates the checksum as it
 * goes. This makes it trivial to update both 16 bit changes (such as length or offset) as well
 * as larger updates like IP address changes.
 *
 * @caution oldp and newp must be at 16bit offsets into the packet or an incorrect checksum will be
 * calculated
 * @caution The checksum is updated in 16bit chunks
 *
 */
void he_calculate_differential_checksum(uint16_t *cksum, void *newp, void *oldp, size_t n);

/**
 * @brief Adjusts the checksums within a packet, to account for a change from `old` to new`.
 * @param packet A pointer to the packet that has been updated.
 * @param length The length of `packet`.
 * @param old The previous value present in `packet`.
 * @param new The new value in `packet` that replaces `old`.
 * @return true on success.
 */
bool he_adjust_packet_checksums(uint8_t *packet, size_t length, uint32_t old, uint32_t new);

#endif  // NETWORK_H
