// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"

// Module Under Test
#include "state.h"

// Internal Dependencies (Not Mocked)
#include "key_hash_methods.h"

// Internal Mocks

#include "mock_hpt_adapter.h"
#include "mock_tun_adapter.h"
#include "mock_tcp_adapter.h"
#include "mock_udp_adapter.h"

#include "mock_conn_repo.h"
#include "mock_conn_service.h"
#include "mock_he_service.h"
#include "mock_inside_ip_repo.h"
#include "mock_plugin_service.h"
#include "mock_user_repo.h"
#include "mock_util.h"

#include "mock_statistics.h"

// Third-Party Mocks
#include "mock_uv.h"
#include "mock_zlog.h"
#include "mock_he.h"

TEST_FIXTURES();

void setUp(void) {
  // Ignore all zlog calls in these tests
  zlogf_time_Ignore();
  zlog_flush_buffer_Ignore();
  zlog_finish_Ignore();
  FIXTURE_SERVER_CONN_SETUP();
}

void tearDown(void) {
  FIXTURE_SERVER_CONN_TEARDOWN();
}

void test_state_initialize_sets_up_libuv_lua(void) {
  uv_loop_t *loop_ptr = (uv_loop_t *)0xDEADBEEF;
  he_server_t state = {0};

  // Expect uv functions calls for setup signal handlers
  uv_default_loop_ExpectAndReturn(loop_ptr);
  uv_loop_set_data_Expect(loop_ptr, &state);
  uv_signal_init_ExpectAndReturn(loop_ptr, &state.sigterm_handle, 0);
  uv_signal_start_ExpectAndReturn(&state.sigterm_handle, NULL /*cb*/, SIGTERM, 0);
  uv_signal_start_IgnoreArg_signal_cb();

  // Expect he_lua functions calls for load lua config file
  he_lua_init_Expect(&state);
  he_lua_dofile_ExpectAndReturn(&state, state.config_file, 0);

  // Ignore other lua functions for getting config values
  copy_global_lua_string_IgnoreAndReturn(jecalloc(1, 1));
  copy_global_lua_string_default_IgnoreAndReturn(jecalloc(1, 1));
  copy_global_lua_string_optional_IgnoreAndReturn(jecalloc(1, 1));
  copy_global_lua_bool_default_IgnoreAndReturn(false);
  copy_global_lua_int_IgnoreAndReturn(0);
  copy_global_lua_int_default_IgnoreAndReturn(0);
  copy_global_lua_double_IgnoreAndReturn(0.0);

  // Ignore other util functions
  ip2int_IgnoreAndReturn(0);
  safe_strncpy_IgnoreAndReturn(NULL);
  zlogf_time_Ignore();
  zlog_finish_Ignore();
  he_statistics_init_start_Ignore();
  he_inside_ip_init_start_Ignore();
  he_conn_repo_init_start_Ignore();
  he_user_repo_init_start_Ignore();
  he_plugin_init_start_Ignore();
  he_service_init_Ignore();
  he_tun_init_Ignore();
  he_udp_init_Ignore();
  he_service_start_Ignore();
  he_tun_start_Ignore();
  he_udp_start_Ignore();

  // Stub calls by he_state_start_global_timers
  uv_timer_init_ExpectAndReturn(loop_ptr, &state.age_timer, 0);
  uv_timer_start_ExpectAndReturn(&state.age_timer, NULL, HE_TIMER_AGE, HE_TIMER_AGE, 0);
  uv_timer_start_IgnoreArg_cb();
  uv_timer_init_ExpectAndReturn(loop_ptr, &state.eviction_timer, 0);
  uv_timer_start_ExpectAndReturn(&state.eviction_timer, NULL, HE_EVICTION_TIMER, HE_EVICTION_TIMER,
                                 0);
  uv_timer_start_IgnoreArg_cb();

  he_state_initialize(&state);
}

void test_state_shutdown(void) {
  uv_loop_t *loop_ptr = (uv_loop_t *)0xDEADBEEF;
  he_server_t state = {
      .loop = loop_ptr,
  };

  he_disconnect_all_connections_Expect(&state);

  // All timers should be stopped
  uv_timer_stop_ExpectAndReturn(&state.age_timer, 0);
  uv_timer_stop_ExpectAndReturn(&state.eviction_timer, 0);
  uv_timer_stop_ExpectAndReturn(&state.stats_timer, 0);

  // The shutdown timer should be started
  uv_timer_init_ExpectAndReturn(loop_ptr, &state.shutdown_timer, 0);
  uv_timer_start_ExpectAndReturn(&state.shutdown_timer, IGNORED_PARAMETER, HE_SHUTDOWN_TIMEOUT_MS,
                                 0, 0);
  uv_timer_start_IgnoreArg_cb();

  he_state_shutdown(&state);

  TEST_ASSERT_TRUE(state.stopping);
}

void test_state_shutdown_stream(void) {
  uv_loop_t *loop_ptr = (uv_loop_t *)0xDEADBEEF;
  he_server_t state = {
      .loop = loop_ptr,
      .connection_type = HE_CONNECTION_TYPE_STREAM,
  };

  // The TCP server should be stopped
  he_tcp_stop_Expect(&state);

  he_disconnect_all_connections_Expect(&state);

  // All timers should be stopped
  uv_timer_stop_ExpectAndReturn(&state.age_timer, 0);
  uv_timer_stop_ExpectAndReturn(&state.eviction_timer, 0);
  uv_timer_stop_ExpectAndReturn(&state.stats_timer, 0);

  // The shutdown timer should be started
  uv_timer_init_ExpectAndReturn(loop_ptr, &state.shutdown_timer, 0);
  uv_timer_start_ExpectAndReturn(&state.shutdown_timer, IGNORED_PARAMETER, HE_SHUTDOWN_TIMEOUT_MS,
                                 0, 0);
  uv_timer_start_IgnoreArg_cb();
  he_state_shutdown(&state);

  TEST_ASSERT_TRUE(state.stopping);
}

void test_state_shutdown_while_stopping(void) {
  uv_loop_t *loop_ptr = (uv_loop_t *)0xDEADBEEF;
  he_server_t state = {
      .loop = loop_ptr,
      .stopping = true,
  };

  // Calling he_state_shutdown while stopping should do nothing and return directly
  he_state_shutdown(&state);

  TEST_ASSERT_TRUE(state.stopping);
}

void test_connection_age_test_no_expire(void) {
  session_connection_map_entry_t entry = {.data = &conn};
  conn.state->ticks_until_no_renegotiation_expiry = 420;

  TEST_ASSERT_FALSE(connection_age_test(&entry));

  TEST_ASSERT_EQUAL(1, conn.absolute_age_count);
  TEST_ASSERT_EQUAL(1, conn.data_age_count);
  TEST_ASSERT_EQUAL(1, conn.stats_age_count);
}

void test_connection_age_test_user_age_out(void) {
  session_connection_map_entry_t entry = {.data = &conn};
  conn.stats_age_count = HE_AGE_TICKS_UNTIL_USER_EXPIRE;

  he_statistics_report_metric_Expect(&conn, HE_METRIC_USER_AGED_OUT);

  TEST_ASSERT_TRUE(connection_age_test(&entry));
}

void test_connection_age_test_old_conn_no_rotation(void) {
  session_connection_map_entry_t entry = {.data = &conn};

  he_conn_supports_renegotiation_ExpectAndReturn(conn.he_conn, false);
  he_statistics_report_metric_Expect(&conn, HE_METRIC_USER_EVICTED_NO_RENEGOTIATION);

  TEST_ASSERT_TRUE(connection_age_test(&entry));
}
