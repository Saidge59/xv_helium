// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"
#include "stub_pkt_maker.h"

// Module Under Test
#include "tun_adapter.h"

// Internal Dependencies (Not Mocked)
#include "util.h"
#include "statistics.h"
#include "network.h"

// Internal Mocks
#include "mock_ip_rewrite.h"
#include "mock_shared_inside_flow.h"
#include "mock_tun.h"

// Third-Party Mocks
#include "mock_statsd-client.h"
#include "mock_zlog.h"

#define TEST_TUN_FD 7
#define TEST_READ_BYTES_RETURNED_FINISHED -1
#define UV_TUN_FLAGS_EMPTY 0

TEST_FIXTURES();

uv_poll_t handle = {0};

void setUp(void) {
  FIXTURE_SERVER_CONN_SETUP();
  handle.data = &server;
  handle.io_watcher.fd = TEST_TUN_FD;

  zlogf_time_Ignore();
  zlog_flush_buffer_Ignore();
}

void tearDown(void) {
  FIXTURE_SERVER_CONN_TEARDOWN();
  memset(&handle, 0, sizeof(handle));
}

// Outdoing flow tests

void test_on_tun_event_non_read_event(void) {
  // It seems as though there's nothing here, but by calling this function
  // without setting up an EXPECT_* beforehand we are asserting that
  // this call doesn't make any other function calls.

  on_tun_event(&handle, IGNORED_PARAMETER, UV_TUN_FLAGS_EMPTY);
}

void test_on_tun_event_blocking_read(void) {
  // Setup test
  read_from_tun_ExpectAndReturn(TEST_TUN_FD, IGNORED_PARAMETER, HE_MAX_OUTSIDE_MTU,
                                TEST_READ_BYTES_RETURNED_FINISHED);
  read_from_tun_IgnoreArg_buf();

  // It seems as though there's nothing here, but by calling this function
  // without setting up an EXPECT_* beforehand we are asserting that
  // this call doesn't make any other function calls.

  on_tun_event(&handle, IGNORED_PARAMETER, UV_READABLE);
}

void test_on_tun_event_packet(void) {
  read_from_tun_ExpectAndReturn(TEST_TUN_FD, IGNORED_PARAMETER, HE_MAX_OUTSIDE_MTU, TEST_BYTES);
  read_from_tun_IgnoreArg_buf();

  he_inside_process_packet_Expect(0, 0, TEST_BYTES);
  he_inside_process_packet_IgnoreArg_state();
  he_inside_process_packet_IgnoreArg_msg_content();

  read_from_tun_ExpectAndReturn(TEST_TUN_FD, IGNORED_PARAMETER, HE_MAX_OUTSIDE_MTU,
                                TEST_READ_BYTES_RETURNED_FINISHED);
  read_from_tun_IgnoreArg_buf();

  on_tun_event(&handle, IGNORED_PARAMETER, UV_READABLE);
}

void test_tun_inside_write_cb_non_dip(void) {
  he_conn_t *he_conn = (he_conn_t *)(intptr_t)0xdeadbeef;
  server.tun_fd = 69;
  conn.data_age_count = 42;

  test_packet *he_packet = fake_string_packet("marker");

  he_rewrite_ip_from_client_to_tun_ipv4_Expect(&conn, he_packet->data, he_packet->len);

  EXPECT_STATSD_COUNT("incoming", he_packet->len);

  write_to_tun_Expect(server.tun_fd, he_packet->data, he_packet->len);

  TEST_ASSERT_EQUAL(HE_SUCCESS,
                    tun_inside_write_cb(he_conn, he_packet->data, he_packet->len, &conn));
  TEST_ASSERT_EQUAL(0, conn.data_age_count);

  jefree(he_packet);
}

void test_tun_inside_write_cb_dip_success(void) {
  he_conn_t *he_conn = (he_conn_t *)(intptr_t)0xdeadbeef;
  server.tun_fd = 69;
  conn.data_age_count = 42;

  server.is_dip_enabled = true;

  test_packet *he_packet = fake_string_packet("a__long__enough__packet");
  ipv4_header_t *ipv4_hdr = (ipv4_header_t *)he_packet->data;
  conn.inside_ip = 666;
  ipv4_hdr->src_addr = 666;

  he_rewrite_ip_from_client_to_tun_ipv4_Expect(&conn, he_packet->data, he_packet->len);

  EXPECT_STATSD_COUNT("incoming", he_packet->len);
  write_to_tun_Expect(server.tun_fd, he_packet->data, he_packet->len);

  TEST_ASSERT_EQUAL(HE_SUCCESS,
                    tun_inside_write_cb(he_conn, he_packet->data, he_packet->len, &conn));
  TEST_ASSERT_EQUAL(0, conn.data_age_count);

  jefree(he_packet);
}

void test_tun_inside_write_cb_dip_drop(void) {
  he_conn_t *he_conn = (he_conn_t *)(intptr_t)0xdeadbeef;
  server.tun_fd = 69;
  conn.data_age_count = 42;

  server.is_dip_enabled = true;

  test_packet *he_packet = fake_string_packet("a__long__enough__packet");
  ipv4_header_t *ipv4_hdr = (ipv4_header_t *)he_packet->data;
  conn.inside_ip = 666;
  ipv4_hdr->src_addr = 667;

  he_rewrite_ip_from_client_to_tun_ipv4_Expect(&conn, he_packet->data, he_packet->len);

  EXPECT_STATSD_INC("invalid_tun_packet_spoofed_inside_ip");

  TEST_ASSERT_EQUAL(HE_SUCCESS,
                    tun_inside_write_cb(he_conn, he_packet->data, he_packet->len, &conn));
  TEST_ASSERT_EQUAL(42, conn.data_age_count);

  jefree(he_packet);
}
