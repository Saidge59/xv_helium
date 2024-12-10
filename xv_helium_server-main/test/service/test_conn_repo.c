// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"

// Module Under Test
#include "conn_repo.h"

// Internal Dependencies (Not Mocked)
#include "key_hash_methods.h"
#include "util.h"
#include "statistics.h"

// Internal Mocks
#include "mock_inside_ip_repo.h"
#include "mock_plugin_service.h"

// Third-Party Mocks
#include "mock_he.h"
#include "mock_statsd-client.h"
#include "mock_uv.h"
#include "mock_zlog.h"

TEST_FIXTURES();

void setUp(void) {
  FIXTURE_SERVER_CONN_SETUP();
  IGNORE_LOGGING_SETUP();
}

void tearDown(void) {
  FIXTURE_SERVER_CONN_TEARDOWN();
}

void test_changeOfAddress_needToImplement(void) {
  TEST_IGNORE_MESSAGE("Need to Implement change_of_address");
}

void test_renegotiation_timer_start(void) {
  server.renegotiation_timer_min = 10;

  uv_timer_start_ExpectAndReturn(&conn.renegotiation_timer, on_renegotiation_timer,
                                 10 * HE_MINUTE_MS, 10 * HE_MINUTE_MS, 0);

  he_connection_start_renegotiation_timer(&conn);
}

void test_on_renegotiation_timer(void) {
  conn.renegotiation_timer.data = &conn;

  he_conn_schedule_renegotiation_ExpectAnyArgsAndReturn(HE_SUCCESS);

  on_renegotiation_timer(&conn.renegotiation_timer);
}

he_return_code_t session_setting_cb(he_conn_t *he_conn, uint64_t *new_session_id, int num_calls) {
  *new_session_id = PENDING_SESSION_ID;

  return HE_SUCCESS;
}

void test_session_id_rotation() {
  conn.pending_session = 0;

  he_conn_rotate_session_id_ExpectAndReturn(conn.he_conn, IGNORED_PARAMETER, HE_SUCCESS);
  he_conn_rotate_session_id_IgnoreArg_new_session_id();
  he_conn_rotate_session_id_AddCallback(session_setting_cb);
  EXPECT_STATSD_INC(HE_METRIC_SESSION_ROTATION_BEGIN);

  he_begin_session_id_rotation(&conn);

  TEST_ASSERT_EQUAL(PENDING_SESSION_ID, conn.pending_session);
}

void test_session_id_rotation_does_not_change_if_pending() {
  conn.pending_session = PENDING_SESSION_ID;

  he_begin_session_id_rotation(&conn);

  TEST_ASSERT_EQUAL(PENDING_SESSION_ID, conn.pending_session);
}

void test_session_id_rotation_finalize() {
  conn.pending_session = PENDING_SESSION_ID;
  conn.cur_session = FOUND_SESSION_ID;

  he_conn_get_session_id_ExpectAndReturn(conn.he_conn, PENDING_SESSION_ID);
  EXPECT_STATSD_INC(HE_METRIC_SESSION_ROTATION_FINALIZE);

  he_finalize_session_id_rotation(&conn);

  TEST_ASSERT_EQUAL(PENDING_SESSION_ID, conn.cur_session);
  TEST_ASSERT_EQUAL(HE_PACKET_SESSION_EMPTY, conn.pending_session);
}

void test_session_id_rotation_finalize_ignores_if_not_pending() {
  conn.cur_session = FOUND_SESSION_ID;
  conn.pending_session = 0x0;

  he_finalize_session_id_rotation(&conn);

  TEST_ASSERT_EQUAL(FOUND_SESSION_ID, conn.cur_session);
  TEST_ASSERT_EQUAL(0, conn.pending_session);
}

void test_he_post_disconnect_cleanup_udp(void) {
  conn.state->connection_type = HE_CONNECTION_TYPE_DATAGRAM;

  //Clear triggers
  uv_timer_stop_ExpectAndReturn(&conn.renegotiation_timer, 0);
  uv_timer_stop_ExpectAndReturn(&conn.he_timer, 0);


  uv_close_Expect(&conn.he_timer, NULL);
  uv_close_IgnoreArg_close_cb();

  he_post_disconnect_cleanup(&conn);
}

void test_he_post_disconnect_cleanup_tcp(void) {
  conn.state->connection_type = HE_CONNECTION_TYPE_STREAM;
  conn.tcp_client_initialized = true;

  //Clear triggers
  uv_timer_stop_ExpectAndReturn(&conn.renegotiation_timer, 0);

  uv_close_Expect(&conn.tcp_client, NULL);
  uv_close_IgnoreArg_close_cb();

  he_post_disconnect_cleanup(&conn);
}

void test_he_post_disconnect_cleanup_tcp_not_initialized(void) {
  conn.state->connection_type = HE_CONNECTION_TYPE_STREAM;
  conn.tcp_client_initialized = false;

  //Clear triggers
  uv_timer_stop_ExpectAndReturn(&conn.renegotiation_timer, 0);

  uv_close_Expect(&conn.renegotiation_timer, NULL);
  uv_close_IgnoreArg_close_cb();

  he_post_disconnect_cleanup(&conn);
}
