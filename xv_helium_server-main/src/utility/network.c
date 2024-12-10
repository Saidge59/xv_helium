#include "network.h"

// Cross platform network headers
#include "inet.h"

void he_calculate_differential_checksum(uint16_t *cksum, void *newp, void *oldp, size_t n) {
  size_t i;
  int32_t accumulate;
  uint16_t *newv = (uint16_t *)newp;
  uint16_t *oldv = (uint16_t *)oldp;

  accumulate = *cksum;
  for(i = 0; i < n; i++) {
    accumulate -= *newv;
    accumulate += *oldv;

    newv++;
    oldv++;
  }

  if(accumulate < 0) {
    accumulate = -accumulate;
    accumulate = (accumulate >> 16) + (accumulate & 0xffff);
    accumulate += accumulate >> 16;
    *cksum = (uint16_t)~accumulate;
  } else {
    accumulate = (accumulate >> 16) + (accumulate & 0xffff);
    accumulate += accumulate >> 16;
    *cksum = (uint16_t)accumulate;
  }
}

/**
 * Returns the offset from the start of the packet to the beginning of the payload
 * Necessary since IP headers can be variable size
 */
uint16_t he_ip_header_payload_offset(ipv4_header_t *header) {
  // ip_hl segment in the ipv4 header is the number of 32 bit (4 byte) words that make up the IP
  // header
  return (header->ver_ihl & 0x0F) * 4;
}

bool he_is_fragmented(ipv4_header_t *header) {
  // IP_MF and IP_DF bits are removed by anding a short all bits except those two set high
  uint16_t fragment_bit_mask = ~(HE_IP_DONT_FRAGMENT | HE_IP_FRAGMENTS_TO_FOLLOW);
  uint16_t offset_without_flags = ntohs(header->flags_fo) & fragment_bit_mask;
  return offset_without_flags != 0;
}

he_packet_state_t he_packet_type(uint8_t *packet, size_t length) {
  // IPv4 is the smallest header for packets we accept
  if(length < sizeof(ipv4_header_t)) {
    return HE_BAD_PACKET;
  }

  // Bits 0-4 of packet contain the IP version
  uint8_t proto = packet[0] >> 4;
  switch(proto) {
    case 4:
      return HE_PACKET_IP4;
    case 6:
      return HE_PACKET_IP6;
    default:
      return HE_BAD_PACKET;
  }
}

bool he_adjust_packet_checksums(uint8_t *packet, size_t length, uint32_t old, uint32_t new) {
  if(length < sizeof(ipv4_header_t)) {
    return false;
  }

  ipv4_header_t *ipv4_hdr = (ipv4_header_t *)packet;
  he_calculate_differential_checksum(&ipv4_hdr->checksum, &new, &old, 2);

  uint16_t payload_start = he_ip_header_payload_offset(ipv4_hdr);

  // The ihl field could be wrong - return false when that is true
  if(payload_start > length) {
    return false;
  }

  uint8_t *payload = packet + payload_start;
  size_t payload_length =
      length -
      payload_start;  // Previous check means that this will always be >= 0, will not overflow

  // Fragmented packets (Packets with a fragmentation offset > 0) do not have headers with
  // checksums.
  if(!he_is_fragmented(ipv4_hdr)) {
    // UDP and TCP have checksums which depend on the client IP so we need to update them
    switch(ipv4_hdr->protocol) {
      case HE_IP_TCP: {
        if(payload_length < sizeof(tcp_header_t)) {
          return false;
        }

        tcp_header_t *tcp_hdr = (tcp_header_t *)payload;
        he_calculate_differential_checksum(&tcp_hdr->checksum, &new, &old, 2);
        break;
      }
      case HE_IP_UDP: {
        if(payload_length < sizeof(udp_header_t)) {
          return false;
        }

        udp_header_t *udp_hdr = (udp_header_t *)payload;

        // UDP checksums are optional and we should respect that when doing NAT
        if(udp_hdr->checksum != 0) {
          he_calculate_differential_checksum(&udp_hdr->checksum, &new, &old, 2);
        }

        break;
      }
      default:
        // TODO: For future you!
        // Important - if any other protocols depend on IP they need a specific switch here!
        break;
    }
  }

  return true;
}
