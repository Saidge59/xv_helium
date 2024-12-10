// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"
#include "mock_fake_dispatch.h"
#include "stub_pkt_maker.h"

// Module Under Test
#include "shared_inside_flow.h"

// Internal Dependencies (Not Mocked)
#include "key_hash_methods.h"
#include "util.h"

// Internal Mocks
#include "mock_ip_rewrite.h"
#include "mock_network.h"

// Third-Party Mocks
#include "mock_he.h"
#include "mock_statsd-client.h"
#include "mock_zlog.h"
#include "mock_uv.h"

#define TEST_READ_BYTES_RETURNED_TINY 5

TEST_FIXTURES();

void setUp(void) {
  FIXTURE_SERVER_CONN_SETUP();

  zlogf_time_Ignore();
  zlog_flush_buffer_Ignore();
  uv_hrtime_IgnoreAndReturn(0);
  // Setup a large queue size
  server.max_socket_queue_size = 1000;
}

void tearDown(void) {
  FIXTURE_SERVER_CONN_TEARDOWN();
}

void test_he_inside_lookup_conn_no_conn_found(void) {
  test_packet *he_packet = fake_string_packet("marker");

  // Return 42 for the IP address; it doesn't matter since the hashmap is empty
  he_extract_dst_ip_ipv4_ExpectAndReturn(he_packet->data, he_packet->len, 42);

  EXPECT_STATSD_INC("rejected_tun_packets");

  // Where are the assertions? Where's the setup?
  // * Because we get a new server for every test, we know the hashmap is
  //   empty and won't return anything
  // * Because we have zero EXPECT_* calls in this test body, we are
  //   asserting this function call returns without calling another function
  he_inside_lookup_conn(&server, he_packet->data, he_packet->len);

  jefree(he_packet);
}

void test_he_inside_lookup_conn_succeeds_udp(void) {
  // Return the connection for a packet
  ip_connection_map_set(&(server.connections_by_inside_ip), 42, &conn);

  test_packet *he_packet = fake_string_packet("marker");

  // Return 42 for the IP address, the same value we set as the IP in the
  // ip_conection_map_set line above
  he_extract_dst_ip_ipv4_ExpectAndReturn(he_packet->data, he_packet->len, 42);

  // Udp queue is empty
  uv_udp_get_send_queue_size_ExpectAndReturn(&server.udp_socket, 0);

  // Ensure that we looked up the IP correctly
  he_rewrite_ip_from_tun_to_client_ipv4_Expect(&conn, he_packet->data, he_packet->len);

  he_conn_inside_packet_received_ExpectAndReturn(conn.he_conn, he_packet->data, he_packet->len, HE_SUCCESS);

  // Note that 7 is the length of marker + ''\0'
  he_inside_lookup_conn(&server, he_packet->data, he_packet->len);

  jefree(he_packet);
}

void test_he_inside_lookup_conn_succeeds_udp_drops_packet(void) {
  // Return the connection for a packet
  ip_connection_map_set(&(server.connections_by_inside_ip), 42, &conn);

  test_packet *he_packet = fake_string_packet("marker");

  // Return 42 for the IP address, the same value we set as the IP in the
  // ip_conection_map_set line above
  he_extract_dst_ip_ipv4_ExpectAndReturn(he_packet->data, he_packet->len, 42);

  // Udp queue is empty
  uv_udp_get_send_queue_size_ExpectAndReturn(&server.udp_socket, 1000);

  // We dropped the packet so no inside_packet_received call

  // Note that 7 is the length of marker + ''\0'
  he_inside_lookup_conn(&server, he_packet->data, he_packet->len);

  jefree(he_packet);
}

void test_he_inside_lookup_conn_succeeds_tcp(void) {
  // Set server to TCP
  server.connection_type = HE_CONNECTION_TYPE_STREAM;

  // Return the connection for a packet
  ip_connection_map_set(&(server.connections_by_inside_ip), 42, &conn);

  test_packet *he_packet = fake_string_packet("marker");

  // Return 42 for the IP address, the same value we set as the IP in the
  // ip_conection_map_set line above
  he_extract_dst_ip_ipv4_ExpectAndReturn(he_packet->data, he_packet->len, 42);

  // TCP Queue is empty
  uv_stream_get_write_queue_size_ExpectAndReturn(&conn.tcp_client, 0);

  // Ensure that we looked up the IP correctly
  he_rewrite_ip_from_tun_to_client_ipv4_Expect(&conn, he_packet->data, he_packet->len);

  he_conn_inside_packet_received_ExpectAndReturn(conn.he_conn, he_packet->data, he_packet->len, HE_SUCCESS);

  // Note that 7 is the length of marker + ''\0'
  he_inside_lookup_conn(&server, he_packet->data, he_packet->len);

  jefree(he_packet);
}

void test_he_inside_lookup_conn_succeeds_tcp_drops_packet(void) {
  // Set server to TCP
  server.connection_type = HE_CONNECTION_TYPE_STREAM;

  // Return the connection for a packet
  ip_connection_map_set(&(server.connections_by_inside_ip), 42, &conn);

  test_packet *he_packet = fake_string_packet("marker");

  // Return 42 for the IP address, the same value we set as the IP in the
  // ip_conection_map_set line above
  he_extract_dst_ip_ipv4_ExpectAndReturn(he_packet->data, he_packet->len, 42);

  // TCP Queue is empty
  uv_stream_get_write_queue_size_ExpectAndReturn(&conn.tcp_client, 1000);

  // We dropped the packet so no inside_packet_received call

  // Note that 7 is the length of marker + ''\0'
  he_inside_lookup_conn(&server, he_packet->data, he_packet->len);

  jefree(he_packet);
}

void test_process_packet_tiny(void) {
  EXPECT_STATSD_COUNT("rejected_tun_packets", 1);
  EXPECT_STATSD_TIMING_WITH_SAMPLE_RATE("outgoing_time")
  EXPECT_STATSD_COUNT("outgoing", 5);

  he_inside_process_packet(&server, IGNORED_PARAMETER, TEST_READ_BYTES_RETURNED_TINY);
}

void test_process_packet_ipv6(void) {
  he_packet_type_ExpectAnyArgsAndReturn(HE_PACKET_IP6);

  EXPECT_STATSD_COUNT("rejected_tun_packets", 1);
  EXPECT_STATSD_TIMING_WITH_SAMPLE_RATE("outgoing_time")
  EXPECT_STATSD_COUNT("outgoing", TEST_BYTES);

  he_inside_process_packet(&server, IGNORED_PARAMETER, TEST_BYTES);
}

void test_process_packet_ipv4(void) {
  he_packet_type_ExpectAnyArgsAndReturn(HE_PACKET_IP4);

  dispatch_Expect("he_inside_lookup_conn");

  EXPECT_STATSD_TIMING_WITH_SAMPLE_RATE("outgoing_time")
  EXPECT_STATSD_COUNT("outgoing", TEST_BYTES);

  he_inside_process_packet(&server, IGNORED_PARAMETER, TEST_BYTES);
}
