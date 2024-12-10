// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"
#include "mock_fake_dispatch.h"
#include "mock_fake_exit.h"
#include "stub_pkt_maker.h"

// Module Under Test
#include "udp_adapter.h"

// Internal Dependencies (Not Mocked)
#include "util.h"

// Internal Mocks
#include "mock_conn_service.h"
#include "mock_statistics.h"

// Third-Party Mocks
#include "mock_he.h"
#include "mock_statsd-client.h"
#include "mock_uv.h"
#include "mock_zlog.h"

TEST_FIXTURES();

uv_buf_t buf = {0};
test_packet *dabbad00 = NULL;

void setUp(void) {
  FIXTURE_SERVER_CONN_SETUP();
  IGNORE_LOGGING_SETUP();
  uv_strerror_IgnoreAndReturn("error");
  dabbad00 = fake_string_packet("dabbad00");
  server.udp_socket.data = &server;
  he_conn_get_session_id_IgnoreAndReturn(FOUND_SESSION_ID);
}

void tearDown(void) {
  FIXTURE_SERVER_CONN_TEARDOWN();
  memset(&buf, 0, sizeof(buf));
  jefree(dabbad00);
  dabbad00 = NULL;
}

#define STUB_SSL_CTX_CALLBACKS()                   \
  he_ssl_ctx_set_outside_write_cb_ExpectAnyArgs(); \
  he_ssl_ctx_set_nudge_time_cb_ExpectAnyArgs()

#define STUB_UDP_INIT_SUCCESS(ip, port)                        \
  uv_ip4_addr_ExpectAndReturn(ip, port, IGNORED_PARAMETER, 0); \
  uv_ip4_addr_IgnoreArg_addr();                                \
  uv_udp_init_ex_ExpectAnyArgsAndReturn(0);                    \
  uv_udp_bind_ExpectAnyArgsAndReturn(0);                       \
  uv_send_buffer_size_ExpectAnyArgsAndReturn(0);               \
  uv_recv_buffer_size_ExpectAnyArgsAndReturn(0)

void test_he_udp_init_success(void) {
  server.udp_socket.data = NULL;

  STUB_SSL_CTX_CALLBACKS();
  STUB_UDP_INIT_SUCCESS(server.bind_ip, server.bind_port);
  he_udp_init(&server);

  TEST_ASSERT_EQUAL_PTR(&server, server.udp_socket.data);
}

void test_he_udp_init_init_fails(void) {
  he_ssl_ctx_set_outside_write_cb_ExpectAnyArgs();
  he_ssl_ctx_set_nudge_time_cb_ExpectAnyArgs();
  uv_ip4_addr_ExpectAnyArgsAndReturn(0);

  uv_udp_init_ex_ExpectAnyArgsAndReturn(-1);

  test_exit_Expect(EXIT_FAILURE);

  he_udp_init(&server);
}

void test_he_udp_init_addr_fails(void) {
  he_ssl_ctx_set_outside_write_cb_ExpectAnyArgs();
  he_ssl_ctx_set_nudge_time_cb_ExpectAnyArgs();

  uv_ip4_addr_ExpectAnyArgsAndReturn(-1);

  test_exit_Expect(EXIT_FAILURE);

  he_udp_init(&server);
}

void test_he_udp_init_bind_fails(void) {
  server.udp_socket.data = NULL;

  he_ssl_ctx_set_outside_write_cb_ExpectAnyArgs();
  he_ssl_ctx_set_nudge_time_cb_ExpectAnyArgs();

  uv_ip4_addr_ExpectAnyArgsAndReturn(0);
  uv_udp_init_ex_ExpectAnyArgsAndReturn(0);
  uv_udp_bind_ExpectAnyArgsAndReturn(-1);

  test_exit_Expect(EXIT_FAILURE);

  he_udp_init(&server);
}

void test_he_udp_init_with_port_scatter(void) {
  server.udp_socket.data = NULL;
  server.port_scatter = true;
  server.port_scatter_ports[1] = 443;
  server.port_scatter_ports[2] = 61024;

  STUB_SSL_CTX_CALLBACKS();

  STUB_UDP_INIT_SUCCESS(server.bind_ip, server.bind_port);
  STUB_UDP_INIT_SUCCESS(server.bind_ip, 443);
  STUB_UDP_INIT_SUCCESS(server.bind_ip, 61024);

  he_udp_init(&server);
}

void test_he_udp_start_success(void) {
  uv_udp_recv_start_ExpectAnyArgsAndReturn(0);
  he_udp_start(&server);
}

void test_he_udp_start_fails(void) {
  uv_udp_recv_start_ExpectAnyArgsAndReturn(-1);

  test_exit_Expect(EXIT_FAILURE);

  he_udp_start(&server);
}

void test_he_udp_start_with_port_scatter(void) {
  server.udp_socket.data = NULL;
  server.port_scatter = true;
  server.port_scatter_ports[1] = 443;
  server.port_scatter_ports[3] = 61024;
  server.he_ctx = (he_ssl_ctx_t *)(uintptr_t)0xdeadbeef;
  uv_udp_recv_start_ExpectAndReturn(&server.udp_socket, alloc_uv_buffer, on_read, 0);

  he_ssl_ctx_set_minimum_supported_version_ExpectAndReturn(server.he_ctx, 1, 2, HE_SUCCESS);

  uv_udp_recv_start_ExpectAndReturn(&server.port_scatter_sockets[1], alloc_uv_buffer, on_read, 0);
  uv_udp_recv_start_ExpectAndReturn(&server.port_scatter_sockets[3], alloc_uv_buffer, on_read, 0);
  he_udp_start(&server);
}

// Server->Client Path

uv_buf_t stub_uv_buf_init(char *output_buffer, unsigned int length, int num_calls) {
  buf.base = output_buffer;
  buf.len = length;
  return buf;
}

int stub_uv_udp_send(uv_udp_send_t *req, uv_udp_t *handle, const uv_buf_t bufs[],
                     unsigned int nbufs, const struct sockaddr *addr, const struct sockaddr *src,
                     uv_udp_send_cb send_cb, int num_calls) {
  TEST_ASSERT_EQUAL_INT(1, nbufs);

  TEST_ASSERT_EQUAL_INT(dabbad00->len, bufs->len);
  TEST_ASSERT_EQUAL_STRING(dabbad00->data, bufs->base);
  // Just double-checking we are copying the data instead of pointing to the origianl buffer
  TEST_ASSERT_NOT_EQUAL((void *)dabbad00->data, (void *)bufs->base);
  on_send_complete(req, 0);

  return 0;
}

void test_udp_write_cb_success(void) {
  he_plugin_egress_ExpectAndReturn(conn.udp_send_plugin_set.plugin_chain, NULL, NULL,
                                   HE_MAX_OUTSIDE_MTU, HE_SUCCESS);
  he_plugin_egress_IgnoreArg_packet();
  he_plugin_egress_IgnoreArg_length();

  uv_buf_init_Stub(stub_uv_buf_init);

  uv_udp_send_Stub(stub_uv_udp_send);

  he_return_code_t res = udp_write_cb(IGNORED_PARAMETER, dabbad00->data, dabbad00->len, &conn);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_udp_write_cb_plugin_drop(void) {
  he_plugin_egress_ExpectAndReturn(conn.udp_send_plugin_set.plugin_chain, NULL, NULL,
                                   HE_MAX_OUTSIDE_MTU, HE_ERR_PLUGIN_DROP);
  he_plugin_egress_IgnoreArg_packet();
  he_plugin_egress_IgnoreArg_length();

  he_return_code_t res = udp_write_cb(IGNORED_PARAMETER, dabbad00->data, dabbad00->len, &conn);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_udp_write_cb_plugin_error(void) {
  he_plugin_egress_ExpectAndReturn(conn.udp_send_plugin_set.plugin_chain, NULL, NULL,
                                   HE_MAX_OUTSIDE_MTU, HE_ERR_NULL_POINTER);
  he_plugin_egress_IgnoreArg_packet();
  he_plugin_egress_IgnoreArg_length();

  he_return_code_t res = udp_write_cb(IGNORED_PARAMETER, dabbad00->data, dabbad00->len, &conn);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_udp_write_cb_send_fail(void) {
  he_plugin_egress_ExpectAndReturn(conn.udp_send_plugin_set.plugin_chain, NULL, NULL,
                                   HE_MAX_OUTSIDE_MTU, HE_SUCCESS);
  he_plugin_egress_IgnoreArg_packet();
  he_plugin_egress_IgnoreArg_length();

  uv_buf_init_Stub(stub_uv_buf_init);

  uv_udp_send_ExpectAnyArgsAndReturn(-1);

  he_return_code_t res = udp_write_cb(IGNORED_PARAMETER, dabbad00->data, dabbad00->len, &conn);

  TEST_ASSERT_EQUAL(HE_ERR_CALLBACK_FAILED, res);
}

// Client->Server Path

void test_on_read_returns_immediately_if_invalid_packet() {
  uv_handle_t handle;
  uv_handle_get_type_ExpectAndReturn(&handle, UV_UDP);
  uv_udp_using_recvmmsg_ExpectAndReturn(&handle, true);
  alloc_uv_buffer(&handle, HE_SERVER_BUFFER_SIZE, &buf);

  struct sockaddr addr = {0};

  uv_hrtime_ExpectAndReturn(0);
  dispatch_bool_ExpectAndReturn("on_read_check_packet_is_valid_helium", false);

  // With no other EXPECT_ statements we are asserting this doesn't call any other functions

  on_read(&server.udp_socket, TEST_BYTES, &buf, &addr, NULL, IGNORED_PARAMETER);

  // buf is freed explicitly before returning
}

void test_on_read_passes_valid_he_pkt_to_flow() {
  uv_handle_t handle;
  uv_handle_get_type_ExpectAndReturn(&handle, UV_UDP);
  uv_udp_using_recvmmsg_ExpectAndReturn(&handle, true);
  alloc_uv_buffer(&handle, HE_SERVER_BUFFER_SIZE, &buf);

  struct sockaddr addr = {0};

  uv_hrtime_ExpectAndReturn(0);
  dispatch_bool_ExpectAndReturn("on_read_check_packet_is_valid_helium", true);

  dispatch_Expect("he_udp_process_valid_packet");

  uv_hrtime_ExpectAndReturn(10 * 100000);

  EXPECT_STATSD_TIMING_WITH_SAMPLE_RATE("incoming_time");

  on_read(&server.udp_socket, TEST_BYTES, &buf, &addr, NULL, IGNORED_PARAMETER);

  // buf is not freed here due to the use of recvmmsg
  jefree(buf.base);
}

void test_on_read_rejects_connection_if_session_expected_but_not_found(void) {
  buf.base = jecalloc(1, HE_SERVER_BUFFER_SIZE);
  buf.len = HE_SERVER_BUFFER_SIZE;

  he_wire_hdr_t *hdr = (he_wire_hdr_t *)buf.base;
  hdr->he[0] = 'H';
  hdr->he[1] = 'e';
  hdr->session = NOT_FOUND_SESSION_ID;

  struct sockaddr_in addr = {0};
  struct sockaddr_in dst = {0};

  addr.sin_family = AF_INET;
  addr.sin_port = TEST_IP_PORT;
  addr.sin_addr.s_addr = TEST_IP_ADDRESS;

  he_v4_ip_port_t test_value = {TEST_IP_ADDRESS, TEST_IP_PORT};

  he_plugin_ingress_ExpectAndReturn(server.udp_recv_plugin_set.plugin_chain, buf.base, NULL,
                                    TEST_BYTES, HE_SUCCESS);
  he_plugin_ingress_IgnoreArg_length();

  he_ssl_ctx_is_supported_version_ExpectAnyArgsAndReturn(true);

  he_find_connection_ExpectAndReturn(&server, NOT_FOUND_SESSION_ID, test_value, IGNORED_PARAMETER,
                                     NULL);
  he_find_connection_IgnoreArg_update_connection_address_out();

  EXPECT_STATSD_INC("rejected_session");
  dispatch_Expect("he_session_reject");

  he_udp_process_valid_packet(&server, NULL, &buf, TEST_BYTES, (const struct sockaddr *)&addr,
                              (const struct sockaddr *)&dst);

  jefree(buf.base);
}

void test_on_read_rejects_connection_if_session_not_found_but_server_stopping(void) {
  buf.base = jecalloc(1, HE_SERVER_BUFFER_SIZE);
  buf.len = HE_SERVER_BUFFER_SIZE;

  he_wire_hdr_t *hdr = (he_wire_hdr_t *)buf.base;
  hdr->he[0] = 'H';
  hdr->he[1] = 'e';
  hdr->session = FOUND_SESSION_ID;

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = TEST_IP_PORT;
  addr.sin_addr.s_addr = TEST_IP_ADDRESS;

  he_v4_ip_port_t test_value = {TEST_IP_ADDRESS, TEST_IP_PORT};

  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_SUCCESS);

  he_ssl_ctx_is_supported_version_ExpectAnyArgsAndReturn(true);

  he_find_connection_ExpectAndReturn(&server, FOUND_SESSION_ID, test_value, IGNORED_PARAMETER,
                                     NULL);
  he_find_connection_IgnoreArg_update_connection_address_out();

  EXPECT_STATSD_INC("rejected_session");
  dispatch_Expect("he_session_reject");

  // Server is stopping
  server.stopping = true;

  he_udp_process_valid_packet(&server, NULL, &buf, TEST_BYTES, (const struct sockaddr *)&addr,
                              NULL);

  jefree(buf.base);
}

void test_on_read_lookups_connection_and_continues(void) {
  buf.base = jecalloc(1, HE_SERVER_BUFFER_SIZE);
  buf.len = HE_SERVER_BUFFER_SIZE;

  he_wire_hdr_t *hdr = (he_wire_hdr_t *)buf.base;
  hdr->he[0] = 'H';
  hdr->he[1] = 'e';
  hdr->session = FOUND_SESSION_ID;

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = TEST_IP_PORT;
  addr.sin_addr.s_addr = TEST_IP_ADDRESS;

  he_v4_ip_port_t test_value = {TEST_IP_ADDRESS, TEST_IP_PORT};

  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_SUCCESS);

  he_ssl_ctx_is_supported_version_ExpectAnyArgsAndReturn(true);

  he_find_connection_ExpectAndReturn(&server, FOUND_SESSION_ID, test_value, IGNORED_PARAMETER,
                                     &conn);
  he_find_connection_IgnoreArg_update_connection_address_out();

  he_conn_outside_data_received_ExpectAndReturn(conn.he_conn, buf.base, TEST_BYTES, HE_SUCCESS);

  he_udp_process_valid_packet(&server, NULL, &buf, TEST_BYTES, (const struct sockaddr *)&addr,
                              NULL);

  jefree(buf.base);
}

void test_on_read_creates_connection_if_needed(void) {
  TEST_IGNORE_MESSAGE("Will come back to this one");
}

void test_on_read_handle_still_connecting(void) {
  TEST_IGNORE_MESSAGE("Gotta come back here too");
}

void test_on_read_handles_change_of_address(void) {
  TEST_IGNORE_MESSAGE("Another to look at closely");
}
