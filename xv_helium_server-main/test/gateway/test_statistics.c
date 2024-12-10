// Test Requirements
#include "unity.h"

#include "statistics.h"

#include "mock_statsd-client.h"
#include "mock_uv.h"
#include "mock_zlog.h"
#include "mock_he.h"

#include "util.h"

void test_he_statistics_init_start() {
  he_server_t state = {.statsd_ip = "192.168.1.1",
                       .statsd_port = 420,
                       .statsd_namespace = "spacename",
                       .statsd_tags = "tags",
                       .loop = (uv_loop_t *)0xdeadbeef};
  statsd_init_with_namespace_tags_ExpectAndReturn(state.statsd_ip, state.statsd_port,
                                                  state.statsd_namespace, state.statsd_tags, 0);
  uv_timer_init_ExpectAndReturn(state.loop, &state.stats_timer, 0);
  uv_timer_start_ExpectAnyArgsAndReturn(0);
  he_statistics_init_start(&state);
  TEST_ASSERT_EQUAL(state.stats_timer.data, &state);
}

void test_he_statistics_report_error_closed_conn() {
  he_server_t state = {.statsd = (statsd_link *)0xbeefbeef};
  he_server_connection_t conn = {.he_conn = (he_conn_t *)0xdeadbeef, .state = &state};

  he_conn_is_error_fatal_ExpectAndReturn(conn.he_conn, HE_ERR_CONNECTION_WAS_CLOSED, false);
  statsd_inc_ExpectAndReturn(state.statsd, HE_METRIC_CONN_CLOSED, 1, 0);
  he_statistics_report_error(&conn, HE_ERR_CONNECTION_WAS_CLOSED);
}

void test_he_statistics_report_error_ssl_error() {
  he_server_t state = {.statsd = (statsd_link *)0xbeefbeef};
  he_server_connection_t conn = {.he_conn = (he_conn_t *)0xdeadbeef, .state = &state};

  // Non-fatal
  he_conn_is_error_fatal_ExpectAndReturn(conn.he_conn, HE_ERR_SSL_ERROR, false);
  he_conn_get_ssl_error_ExpectAndReturn(conn.he_conn, 0);
  statsd_inc_ExpectAndReturn(state.statsd, "non_fatal_ssl_error", 1, 0);
  he_statistics_report_error(&conn, HE_ERR_SSL_ERROR);

  // Fatal
  he_conn_is_error_fatal_ExpectAndReturn(conn.he_conn, HE_ERR_SSL_ERROR, true);
  he_conn_get_ssl_error_ExpectAndReturn(conn.he_conn, 0);
  statsd_inc_ExpectAndReturn(state.statsd, "ssl_error", 1, 0);
  he_statistics_report_error(&conn, HE_ERR_SSL_ERROR);

  // Non-fatal with ssl error code
  he_conn_is_error_fatal_ExpectAndReturn(conn.he_conn, HE_ERR_SSL_ERROR, false);
  he_conn_get_ssl_error_ExpectAndReturn(conn.he_conn, -323);
  statsd_inc_ExpectAndReturn(state.statsd, "non_fatal_ssl_error_323", 1, 0);
  he_statistics_report_error(&conn, HE_ERR_SSL_ERROR);

  // Fatal with ssl error code
  he_conn_is_error_fatal_ExpectAndReturn(conn.he_conn, HE_ERR_SSL_ERROR, true);
  he_conn_get_ssl_error_ExpectAndReturn(conn.he_conn, -323);
  statsd_inc_ExpectAndReturn(state.statsd, "ssl_error_323", 1, 0);
  he_statistics_report_error(&conn, HE_ERR_SSL_ERROR);
}

void test_he_statistics_report_error_secure_renegotiation() {
  he_server_t state = {.statsd = (statsd_link *)0xbeefbeef};
  he_server_connection_t conn = {.he_conn = (he_conn_t *)0xdeadbeef, .state = &state};

  he_conn_is_error_fatal_ExpectAndReturn(conn.he_conn, HE_ERR_SECURE_RENEGOTIATION_ERROR, false);
  statsd_inc_ExpectAndReturn(state.statsd, HE_METRIC_SECURE_RENEGOTIATION_ERROR, 1, 0);
  he_statistics_report_error(&conn, HE_ERR_SECURE_RENEGOTIATION_ERROR);
}

void test_he_statistics_report_error_generic_errors() {
  he_server_t state = {.statsd = (statsd_link *)0xbeefbeef};
  he_server_connection_t conn = {.he_conn = (he_conn_t *)0xdeadbeef, .state = &state};

  for(int i = HE_ERR_STRING_TOO_LONG; i >= HE_ERR_SECURE_RENEGOTIATION_ERROR; --i) {
    // Ignore specific errors
    if(i == HE_ERR_SSL_ERROR || i == HE_ERR_CONNECTION_WAS_CLOSED ||
       i == HE_ERR_SECURE_RENEGOTIATION_ERROR || i == HE_ERR_SERVER_GOODBYE) {
      continue;
    }

    char metric[HE_METRIC_MAX_LENGTH] = {0};

    // Non-fatal
    he_conn_is_error_fatal_ExpectAndReturn(conn.he_conn, i, false);
    snprintf(metric, sizeof(metric), "unknown_non_fatal_error_%d", abs(i));
    statsd_inc_ExpectAndReturn(state.statsd, metric, 1, 0);
    he_statistics_report_error(&conn, i);

    // Fatal
    he_conn_is_error_fatal_ExpectAndReturn(conn.he_conn, i, true);
    snprintf(metric, sizeof(metric), "unknown_fatal_error_%d", abs(i));
    statsd_inc_ExpectAndReturn(state.statsd, metric, 1, 0);
    he_statistics_report_error(&conn, i);
  }
}

void test_he_statistics_report_error_ignored_errors() {
  he_server_t state = {.statsd = (statsd_link *)0xbeefbeef};
  he_server_connection_t conn = {.he_conn = (he_conn_t *)0xdeadbeef, .state = &state};

  // HE_SUCCESS
  he_conn_is_error_fatal_ExpectAndReturn(conn.he_conn, HE_SUCCESS, false);
  he_statistics_report_error(&conn, HE_SUCCESS);

  // HE_ERR_SERVER_GOODBYE
  he_conn_is_error_fatal_ExpectAndReturn(conn.he_conn, HE_ERR_SERVER_GOODBYE, true);
  he_statistics_report_error(&conn, HE_ERR_SERVER_GOODBYE);
}
