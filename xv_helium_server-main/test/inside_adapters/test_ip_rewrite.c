// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"

// Module Under Test
#include "ip_rewrite.h"

#include "mock_network.h"

TEST_FIXTURES();

void setUp(void) {
  FIXTURE_SERVER_CONN_SETUP();
  server.client_ip_u32 = 420420420;
  conn.inside_ip = 69696969;
}

void tearDown(void) {
  FIXTURE_SERVER_CONN_TEARDOWN();
}

void test_he_rewrite_ip_from_client_to_tun_ipv4(void) {
    ipv4_header_t hdr = {0};
    uint8_t *packet = (uint8_t *)&hdr;
    he_adjust_packet_checksums_ExpectAndReturn(packet, sizeof(ipv4_header_t),
                                               server.client_ip_u32, conn.inside_ip, true);
    he_rewrite_ip_from_client_to_tun_ipv4(&conn, (uint8_t *)&hdr, sizeof(ipv4_header_t));
    TEST_ASSERT_EQUAL(hdr.src_addr, conn.inside_ip);
}

void test_he_rewrite_ip_from_tun_to_client_ipv4(void) {
    ipv4_header_t hdr = {0};
    uint8_t *packet = (uint8_t *)&hdr;
    he_adjust_packet_checksums_ExpectAndReturn(packet, sizeof(ipv4_header_t),
                                               conn.inside_ip, server.client_ip_u32, true);
    he_rewrite_ip_from_tun_to_client_ipv4(&conn, (uint8_t *)&hdr, sizeof(ipv4_header_t));
    TEST_ASSERT_EQUAL(hdr.dst_addr, server.client_ip_u32);
}
