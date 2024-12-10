// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"
#include "mock_fake_dispatch.h"
#include "mock_fake_exit.h"
#include "stub_pkt_maker.h"

// Module Under Test
#include "tcp_adapter.h"

// Internal Dependencies (Not Mocked)
#include "util.h"
#include "tcp_proxy.h"
#include <jemalloc.h>

// Internal Mocks
#include "mock_conn_service.h"
#include "mock_statistics.h"

// Third-Party Mocks
#include "mock_he.h"
#include "mock_statsd-client.h"
#include "mock_uv.h"
#include "mock_zlog.h"

// General Includes

TEST_FIXTURES();

uv_buf_t buf = {0};
test_packet *dabbad00 = NULL;

void setUp(void) {
  memset(&server, 0, sizeof(server));
  memset(&conn, 0, sizeof(conn));
  FIXTURE_SERVER_CONN_SETUP();
  IGNORE_LOGGING_SETUP();
  uv_strerror_IgnoreAndReturn("error");
  dabbad00 = fake_string_packet("dabbad00");
  server.tcp_server.data = &server;
  conn.tcp_client.data = &conn;
}

void tearDown(void) {
  FIXTURE_SERVER_CONN_TEARDOWN();
  memset(&buf, 0, sizeof(buf));
  jefree(dabbad00);
  dabbad00 = NULL;
}

// Public API Tests

void test_init_server_configures_server(void) {
  server.tcp_server.data = NULL;
  // There's no point checking args here, since they are all pointers initialised to NULL in the
  // setup anyway
  he_ssl_ctx_set_outside_write_cb_ExpectAnyArgs();

  uv_tcp_init_ExpectAnyArgsAndReturn(0);

  uv_ip4_addr_ExpectAnyArgsAndReturn(0);

  uv_tcp_bind_ExpectAnyArgsAndReturn(0);

  he_tcp_init(&server);

  TEST_ASSERT_EQUAL_PTR(&server, server.tcp_server.data);
}

void test_init_server_configures_server_ipv6(void) {
  server.tcp_server.data = NULL;
  // There's no point checking args here, since they are all pointers initialised to NULL in the
  // setup anyway
  he_ssl_ctx_set_outside_write_cb_ExpectAnyArgs();

  uv_tcp_init_ExpectAnyArgsAndReturn(0);

  uv_ip4_addr_ExpectAnyArgsAndReturn(-1);
  uv_ip6_addr_ExpectAnyArgsAndReturn(0);

  uv_tcp_bind_ExpectAnyArgsAndReturn(0);

  he_tcp_init(&server);

  TEST_ASSERT_EQUAL_PTR(&server, server.tcp_server.data);
}

void test_init_server_handles_tcp_init_err(void) {
  he_ssl_ctx_set_outside_write_cb_ExpectAnyArgs();

  uv_tcp_init_ExpectAnyArgsAndReturn(-1);

  test_exit_Expect(EXIT_FAILURE);

  he_tcp_init(&server);
}

void test_init_server_handles_bad_ip_addr(void) {
  he_ssl_ctx_set_outside_write_cb_ExpectAnyArgs();

  uv_tcp_init_ExpectAnyArgsAndReturn(0);

  uv_ip4_addr_ExpectAnyArgsAndReturn(-1);
  uv_ip6_addr_ExpectAnyArgsAndReturn(-1);

  test_exit_Expect(EXIT_FAILURE);

  he_tcp_init(&server);
}

void test_init_server_handles_bind_failure(void) {
  he_ssl_ctx_set_outside_write_cb_ExpectAnyArgs();

  uv_tcp_init_ExpectAnyArgsAndReturn(0);

  uv_ip4_addr_ExpectAnyArgsAndReturn(0);

  uv_tcp_bind_ExpectAnyArgsAndReturn(-1);

  test_exit_Expect(EXIT_FAILURE);

  he_tcp_init(&server);
}

void test_start_server_success(void) {
  uv_listen_ExpectAnyArgsAndReturn(0);

  he_tcp_start(&server);
}

void test_start_server_failure(void) {
  uv_listen_ExpectAnyArgsAndReturn(-1);

  test_exit_Expect(EXIT_FAILURE);

  he_tcp_start(&server);
}

void test_stop_server(void) {
  uv_listen_ExpectAnyArgsAndReturn(0);

  he_tcp_start(&server);

  uv_close_Expect((uv_handle_t *)&server.tcp_server, on_tcp_stopped);
  he_tcp_stop(&server);
}

// Server->Client Path
uv_buf_t stub_uv_buf_init(char *output_buffer, unsigned int length, int num_calls) {
  buf.base = output_buffer;
  buf.len = length;
  return buf;
}

int stub_uv_write(uv_write_t *req, uv_stream_t *handle, const uv_buf_t bufs[], unsigned int nbufs,
                  uv_write_cb cb, int num_calls) {
  TEST_ASSERT_EQUAL_INT(1, nbufs);

  TEST_ASSERT_EQUAL_INT(dabbad00->len, bufs->len);
  TEST_ASSERT_EQUAL_STRING(dabbad00->data, bufs->base);
  // Just double-checking we are copying the data instead of pointing to the original buffer
  TEST_ASSERT_NOT_EQUAL((void *)dabbad00->data, (void *)bufs->base);
  on_send_streaming((uv_write_t *)req, 0);

  return 0;
}

void test_tcp_write_cb_success(void) {
  he_plugin_egress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  uv_buf_init_Stub(stub_uv_buf_init);
  uv_write_Stub(stub_uv_write);

  he_return_code_t res = tcp_write_cb(IGNORED_PARAMETER, dabbad00->data, dabbad00->len, &conn);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_tcp_write_cb_plugin_drop(void) {
  he_plugin_egress_ExpectAnyArgsAndReturn(HE_ERR_PLUGIN_DROP);

  he_return_code_t res = tcp_write_cb(IGNORED_PARAMETER, dabbad00->data, dabbad00->len, &conn);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_tcp_write_cb_plugin_fail(void) {
  he_plugin_egress_ExpectAnyArgsAndReturn(HE_ERR_NULL_POINTER);

  he_return_code_t res = tcp_write_cb(IGNORED_PARAMETER, dabbad00->data, dabbad00->len, &conn);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_tcp_write_cb_write_fail(void) {
  he_plugin_egress_ExpectAnyArgsAndReturn(HE_SUCCESS);

  uv_buf_init_Stub(stub_uv_buf_init);

  uv_write_ExpectAnyArgsAndReturn(-1);

  he_return_code_t res = tcp_write_cb(IGNORED_PARAMETER, dabbad00->data, dabbad00->len, &conn);

  TEST_ASSERT_EQUAL(HE_ERR_CALLBACK_FAILED, res);
}

// Client->Server Path

void test_tcp_new_connection_success(void) {
  he_create_new_connection_streaming_ExpectAndReturn(&server, &conn);

  uv_tcp_init_ExpectAnyArgsAndReturn(0);

  uv_accept_ExpectAndReturn((uv_stream_t *)&server.tcp_server, (uv_stream_t *)&conn.tcp_client, 0);
  // We test this works as expected in a later test
  uv_tcp_getpeername_ExpectAnyArgsAndReturn(0);

  uv_read_start_ExpectAnyArgsAndReturn(0);

  on_new_streaming_connection((uv_stream_t *)&server.tcp_server, 0);
  TEST_ASSERT_TRUE(conn.tcp_client_initialized);
}

void test_tcp_new_connection_dip_success(void) {
  server.is_dip_enabled = true;

  he_create_new_connection_streaming_ExpectAndReturn(&server, &conn);

  uv_tcp_init_ExpectAnyArgsAndReturn(0);

  uv_accept_ExpectAndReturn((uv_stream_t *)&server.tcp_server, (uv_stream_t *)&conn.tcp_client, 0);

  uv_tcp_getsockname_ExpectAndReturn(&conn.tcp_client, &conn.dip_addr, NULL, 0);
  uv_tcp_getsockname_IgnoreArg_namelen();
  uv_tcp_getpeername_ExpectAnyArgsAndReturn(0);

  uv_read_start_ExpectAnyArgsAndReturn(0);

  on_new_streaming_connection((uv_stream_t *)&server.tcp_server, 0);
  TEST_ASSERT_TRUE(conn.tcp_client_initialized);
}

void test_tcp_new_connection_no_conn_created(void) {
  he_create_new_connection_streaming_ExpectAndReturn(&server, NULL);

  on_new_streaming_connection((uv_stream_t *)&server.tcp_server, 0);
}

void test_tcp_new_connection_init_fails(void) {
  he_create_new_connection_streaming_ExpectAndReturn(&server, &conn);

  uv_tcp_init_ExpectAnyArgsAndReturn(-1);

  he_connection_disconnect_Expect(&conn);

  on_new_streaming_connection((uv_stream_t *)&server.tcp_server, 0);

  // Failure to initialize must ensure this bool is false
  TEST_ASSERT_FALSE(conn.tcp_client_initialized);
}

void test_tcp_new_connection_accept_fails(void) {
  he_create_new_connection_streaming_ExpectAndReturn(&server, &conn);

  uv_tcp_init_ExpectAnyArgsAndReturn(0);

  uv_accept_ExpectAnyArgsAndReturn(-1);

  he_connection_disconnect_Expect(&conn);

  on_new_streaming_connection((uv_stream_t *)&server.tcp_server, 0);
}

void test_tcp_new_connection_getsockname_fails(void) {
  server.is_dip_enabled = true;

  he_create_new_connection_streaming_ExpectAndReturn(&server, &conn);

  uv_tcp_init_ExpectAnyArgsAndReturn(0);

  uv_accept_ExpectAnyArgsAndReturn(0);

  // Disconnect if failed to getsockname from the tcp connection
  uv_tcp_getsockname_ExpectAndReturn(&conn.tcp_client, &conn.dip_addr, NULL, -1);
  uv_tcp_getsockname_IgnoreArg_namelen();
  he_connection_disconnect_Expect(&conn);

  on_new_streaming_connection((uv_stream_t *)&server.tcp_server, 0);
}

void test_tcp_new_connection_get_peername_fails(void) {
  he_create_new_connection_streaming_ExpectAndReturn(&server, &conn);

  uv_tcp_init_ExpectAnyArgsAndReturn(0);

  uv_accept_ExpectAnyArgsAndReturn(0);

  // Not fatal!
  uv_tcp_getpeername_ExpectAnyArgsAndReturn(-1);

  uv_read_start_ExpectAnyArgsAndReturn(0);

  on_new_streaming_connection((uv_stream_t *)&server.tcp_server, 0);
}

void test_tcp_new_connection_read_start_fails(void) {
  he_create_new_connection_streaming_ExpectAndReturn(&server, &conn);

  uv_tcp_init_ExpectAnyArgsAndReturn(0);

  uv_accept_ExpectAnyArgsAndReturn(0);

  uv_tcp_getpeername_ExpectAnyArgsAndReturn(0);

  uv_read_start_ExpectAnyArgsAndReturn(-1);

  he_connection_disconnect_Expect(&conn);

  on_new_streaming_connection((uv_stream_t *)&server.tcp_server, 0);
}

int stub_uv_tcp_getpeername(const uv_tcp_t *handle, struct sockaddr *name, int *namelen,
                            int num_calls) {
  struct sockaddr_in *in_name = (struct sockaddr_in *)name;
  in_name->sin_family = AF_INET;
  in_name->sin_port = TEST_IP_PORT;
  in_name->sin_addr.s_addr = TEST_IP_ADDRESS;

  return 0;
}

void test_tcp_new_connection_sets_ip_address(void) {
  he_create_new_connection_streaming_ExpectAnyArgsAndReturn(&conn);

  uv_tcp_init_ExpectAnyArgsAndReturn(0);
  uv_accept_ExpectAnyArgsAndReturn(0);

  uv_tcp_getpeername_Stub(stub_uv_tcp_getpeername);

  uv_read_start_ExpectAnyArgsAndReturn(0);

  on_new_streaming_connection((uv_stream_t *)&server.tcp_server, 0);

  he_v4_ip_port_t test_value = {TEST_IP_ADDRESS, TEST_IP_PORT};

  TEST_ASSERT_EQUAL_MEMORY(&test_value, &conn.external_ip_port, sizeof(test_value));
}

void test_on_tcp_read_success(void) {
  conn.tcp_first_byte_seen = true;

  stub_uv_buf_init((char *)dabbad00->data, dabbad00->len, 0);

  uv_hrtime_ExpectAndReturn(0);

  dispatch_Expect("he_tcp_outside_stream_received");

  uv_hrtime_ExpectAndReturn(10 * 1000000);

  EXPECT_STATSD_TIMING_WITH_SAMPLE_RATE("incoming_time");

  on_tcp_read((uv_stream_t *)&conn.tcp_client, dabbad00->len, &buf);

  TEST_ASSERT_TRUE_MESSAGE(conn.tcp_first_byte_seen, "tcp_first_byte_seen should be set");
}

void test_on_tcp_read_error(void) {
  stub_uv_buf_init((char *)dabbad00->data, dabbad00->len, 0);

  he_connection_disconnect_Expect(&conn);

  on_tcp_read((uv_stream_t *)&conn.tcp_client, -42, &buf);
}

void test_on_tcp_read_zero(void) {
  stub_uv_buf_init((char *)dabbad00->data, dabbad00->len, 0);

  // Nothing happens!
  on_tcp_read((uv_stream_t *)&conn.tcp_client, 0, &buf);
}

void test_on_tcp_read_proxy_hdr(void) {
  uint8_t *testdata = (uint8_t *)jemalloc(512);

  uint8_t sig[] = {
      0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,  // sig
  };
  proxy_hdr_v2_t *hdr = (proxy_hdr_v2_t *)testdata;
  memcpy(hdr->sig, sig, sizeof(sig));
  hdr->ver_cmd = 2;
  hdr->fam = AF_INET;
  hdr->len = htons(12);
  proxy_addr_t *addr = (proxy_addr_t *)&testdata[sizeof(proxy_hdr_v2_t)];
  addr->ipv4_addr.src_addr = ip2int("12.34.56.78");
  addr->ipv4_addr.src_port = 60123;
  addr->ipv4_addr.dst_addr = ip2int("89.67.45.23");
  addr->ipv4_addr.dst_port = 443;

  size_t nread = sizeof(proxy_hdr_v2_t) + 12;
  stub_uv_buf_init((char *)testdata, nread, 0);

  on_tcp_read((uv_stream_t *)&conn.tcp_client, nread, &buf);

  TEST_ASSERT_TRUE(conn.tcp_first_byte_seen);
  TEST_ASSERT_TRUE(conn.tcp_is_proxied);
  TEST_ASSERT_EQUAL(addr->ipv4_addr.src_addr, conn.external_ip_port.ip);
  TEST_ASSERT_EQUAL(addr->ipv4_addr.src_port, conn.external_ip_port.port);
  TEST_ASSERT_EQUAL(addr->ipv4_addr.dst_addr, conn.tcp_proxied_bind_ip_port.ip);
  TEST_ASSERT_EQUAL(addr->ipv4_addr.dst_port, conn.tcp_proxied_bind_ip_port.port);
}

void test_he_tcp_outside_stream_success(void) {
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_SUCCESS);

  he_conn_outside_data_received_ExpectAndReturn(conn.he_conn, dabbad00->data, dabbad00->len,
                                                HE_SUCCESS);

  he_tcp_outside_stream_received(&conn, dabbad00->data, dabbad00->len);
}

void test_he_tcp_outside_stream_plugin_drop(void) {
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_ERR_PLUGIN_DROP);

  he_tcp_outside_stream_received(&conn, dabbad00->data, dabbad00->len);
}

void test_he_tcp_outside_stream_plugin_fail(void) {
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_ERR_NULL_POINTER);

  he_statistics_report_metric_Expect(&conn, "plugin_error");

  he_tcp_outside_stream_received(&conn, dabbad00->data, dabbad00->len);
}

void test_he_tcp_outside_stream_he_error_fatal_disconnects(void) {
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_SUCCESS);

  he_conn_outside_data_received_ExpectAndReturn(conn.he_conn, dabbad00->data, dabbad00->len,
                                                HE_ERR_NULL_POINTER);
  he_return_code_name_ExpectAndReturn(HE_ERR_NULL_POINTER, "err");

  he_conn_is_error_fatal_ExpectAndReturn(conn.he_conn, HE_ERR_NULL_POINTER, true);

  he_statistics_report_error_Expect(&conn, HE_ERR_NULL_POINTER);

  he_connection_disconnect_Expect(&conn);

  he_tcp_outside_stream_received(&conn, dabbad00->data, dabbad00->len);
}

void test_he_tcp_outside_stream_he_error_nonfatal_no_disconnect(void) {
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_SUCCESS);

  he_conn_outside_data_received_ExpectAndReturn(conn.he_conn, dabbad00->data, dabbad00->len,
                                                HE_ERR_NULL_POINTER);
  he_return_code_name_ExpectAndReturn(HE_ERR_NULL_POINTER, "err");

  he_conn_is_error_fatal_ExpectAndReturn(conn.he_conn, HE_ERR_NULL_POINTER, false);

  he_statistics_report_error_Expect(&conn, HE_ERR_NULL_POINTER);

  he_tcp_outside_stream_received(&conn, dabbad00->data, dabbad00->len);
}
