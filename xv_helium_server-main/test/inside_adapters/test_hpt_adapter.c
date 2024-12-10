// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"
#include "stub_pkt_maker.h"

// Module Under Test
#include "hpt_adapter.h"

// Internal Dependencies (Not Mocked)
#include "util.h"
#include "statistics.h"
#include "network.h"

// Internal Mocks
#include "mock_ip_rewrite.h"
#include "mock_shared_inside_flow.h"

// Third-Party Mocks
#include "mock_hpt.h"
#include "mock_statsd-client.h"
#include "mock_zlog.h"
#include "mock_he.h"
#include "mock_uv.h"

TEST_FIXTURES();

void setUp(void) {
  FIXTURE_SERVER_CONN_SETUP();
  zlogf_time_Ignore();
}

void tearDown(void) {
  FIXTURE_SERVER_CONN_TEARDOWN();
}

void test_he_hpt_init(void) {
  server.he_ctx = (he_ssl_ctx_t *)0xdeadbeef;
  server.tun_device = "test";
  server.hpt_kthread_idle_usec = 100;
  he_ssl_ctx_set_inside_write_cb_Expect(server.he_ctx, hpt_inside_write_cb);
  hpt_init_ExpectAndReturn(0);

  struct hpt *hpt = (struct hpt *)0xdeaddead;
  hpt_alloc_ExpectAndReturn(server.tun_device, 8192, on_hpt_packet, &server, server.hpt_kthread_idle_usec, hpt);
  int wake_fd = 42;
  hpt_wake_fd_ExpectAndReturn(wake_fd);
  uv_poll_init_ExpectAndReturn(server.loop, &server.uv_hpt, wake_fd, 0);

  he_hpt_init(&server);

  TEST_ASSERT_EQUAL(hpt, server.hpt);
  TEST_ASSERT_EQUAL(&server, server.uv_hpt.data);
}

void test_on_hpt_event(void) {
  server.hpt = (struct hpt *)0xdeadbeef;
  uv_poll_t uv = {.data = (void *)&server};
  hpt_drain_Expect(server.hpt);

  on_hpt_event(&uv, 0, 0);
}

void test_on_hpt_packet(void) {
  uint8_t msg[10] = {0};

  he_inside_process_packet_Expect(&server, msg, sizeof(msg));
  on_hpt_packet(&server, msg, sizeof(msg));
}

void test_hpt_inside_write_cb_too_small(void) {
  he_conn_t *he_conn = (he_conn_t *)(intptr_t)0xdeadbeef;
  uint8_t msg[1] = {0};
  EXPECT_STATSD_INC("invalid_hpt_packet_zero_size");
  TEST_ASSERT_EQUAL(HE_SUCCESS, hpt_inside_write_cb(he_conn, msg, 0, &conn));
}

void test_hpt_inside_write_cb_too_big(void) {
  he_conn_t *he_conn = (he_conn_t *)(intptr_t)0xdeadbeef;
  uint8_t msg[1] = {0};
  EXPECT_STATSD_INC("invalid_hpt_packet_over_sized");
  TEST_ASSERT_EQUAL(HE_SUCCESS, hpt_inside_write_cb(he_conn, msg, 99999999999, &conn));
}

void test_hpt_inside_write_cb_non_dip(void) {
  he_conn_t *he_conn = (he_conn_t *)(intptr_t)0xdeadbeef;
  test_packet *he_packet = fake_string_packet("amogus");
  server.hpt = (struct hpt *)(intptr_t)0xdeadc0de;
  conn.data_age_count = 42;

  he_rewrite_ip_from_client_to_tun_ipv4_Expect(&conn, he_packet->data, he_packet->len);
  EXPECT_STATSD_COUNT("incoming", he_packet->len);
  hpt_write_Expect(server.hpt, he_packet->data, he_packet->len);

  TEST_ASSERT_EQUAL(HE_SUCCESS,
                    hpt_inside_write_cb(he_conn, he_packet->data, he_packet->len, &conn));
  TEST_ASSERT_EQUAL(0, conn.data_age_count);
  jefree(he_packet);
}

void test_hpt_inside_write_cb_dip_success(void) {
  he_conn_t *he_conn = (he_conn_t *)(intptr_t)0xdeadbeef;
  server.hpt = (struct hpt *)(intptr_t)0xdeadc0de;
  conn.data_age_count = 42;

  server.is_dip_enabled = true;

  test_packet *he_packet = fake_string_packet("a__long__enough__packet");
  ipv4_header_t *ipv4_hdr = (ipv4_header_t *)he_packet->data;
  conn.inside_ip = 666;
  ipv4_hdr->src_addr = 666;

  he_rewrite_ip_from_client_to_tun_ipv4_Expect(&conn, he_packet->data, he_packet->len);

  EXPECT_STATSD_COUNT("incoming", he_packet->len);
  hpt_write_Expect(server.hpt, he_packet->data, he_packet->len);

  TEST_ASSERT_EQUAL(HE_SUCCESS,
                    hpt_inside_write_cb(he_conn, he_packet->data, he_packet->len, &conn));
  TEST_ASSERT_EQUAL(0, conn.data_age_count);
  jefree(he_packet);
}

void test_hpt_inside_write_cb_dip_drop(void) {
  he_conn_t *he_conn = (he_conn_t *)(intptr_t)0xdeadbeef;
  server.hpt = (struct hpt *)(intptr_t)0xdeadc0de;
  conn.data_age_count = 42;

  server.is_dip_enabled = true;

  test_packet *he_packet = fake_string_packet("a__long__enough__packet");
  ipv4_header_t *ipv4_hdr = (ipv4_header_t *)he_packet->data;
  conn.inside_ip = 666;
  ipv4_hdr->src_addr = 667;

  he_rewrite_ip_from_client_to_tun_ipv4_Expect(&conn, he_packet->data, he_packet->len);

  EXPECT_STATSD_INC("invalid_hpt_packet_spoofed_inside_ip");

  TEST_ASSERT_EQUAL(HE_SUCCESS,
                    hpt_inside_write_cb(he_conn, he_packet->data, he_packet->len, &conn));
  TEST_ASSERT_EQUAL(42, conn.data_age_count);
  jefree(he_packet);
}
