#ifndef HE_TEST_DEFINITIONS
#define HE_TEST_DEFINITIONS

#define EXPECT_STATSD_TIMING_WITH_SAMPLE_RATE(stat)                   \
  statsd_timing_with_sample_rate_ExpectAndReturn(0, (stat), 1, 0, 0); \
  statsd_timing_with_sample_rate_IgnoreArg_link();                    \
  statsd_timing_with_sample_rate_IgnoreArg_ms();                      \
  statsd_timing_with_sample_rate_IgnoreArg_sample_rate();

#define EXPECT_STATSD_COUNT(stat, value)                  \
  statsd_count_ExpectAndReturn(0, (stat), (value), 0, 0); \
  statsd_count_IgnoreArg_link();                          \
  statsd_count_IgnoreArg_sample_rate();

#define EXPECT_STATSD_INC(stat)                \
  statsd_inc_ExpectAndReturn(0, (stat), 0, 0); \
  statsd_inc_IgnoreArg_link();                 \
  statsd_inc_IgnoreArg_sample_rate();

#define EXPECT_STATSD_TIMING(stat)                \
  statsd_timing_ExpectAndReturn(0, (stat), 1, 0); \
  statsd_timing_IgnoreArg_link();                 \
  statsd_timing_IgnoreArg_ms();

#define IGNORE_LOGGING_SETUP() \
  zlogf_time_Ignore();         \
  zlog_finish_Ignore();        \
  zlog_flush_buffer_Ignore();

#define IGNORED_PARAMETER 0
#define TEST_BYTES 42

// IP Address: 203.0.113.5
#define TEST_IP_ADDRESS htonl(3405803781)
#define TEST_IP_PORT htons(32123)

#define NOT_FOUND_SESSION_ID 1234
#define FOUND_SESSION_ID 4321
#define PENDING_SESSION_ID 9876

#define TEST_FIXTURES()     \
  he_server_t server = {0}; \
  he_server_connection_t conn = {0};

#define FIXTURE_SERVER_SETUP()                                              \
  server.statsd = (statsd_link *)(uintptr_t)0x1357feed;                     \
  ip_connection_map_init(&server.connections_by_inside_ip);                 \
  ip_port_connection_map_init(&server.connections_by_external_ip_and_port); \
  session_connection_map_init(&server.connections_by_session);              \
  session_connection_map_init(&server.connections_by_pending_session);

#define FIXTURE_SERVER_CONN_SETUP() \
  FIXTURE_SERVER_SETUP();           \
  conn.state = &server;

#define FIXTURE_SERVER_TEARDOWN()                                           \
  session_connection_map_free(&server.connections_by_session);              \
  session_connection_map_free(&server.connections_by_pending_session);      \
  ip_port_connection_map_free(&server.connections_by_external_ip_and_port); \
  ip_connection_map_free(&server.connections_by_inside_ip);                 \
  memset(&server, 0, sizeof(server));

#define FIXTURE_SERVER_CONN_TEARDOWN() \
  FIXTURE_SERVER_TEARDOWN();           \
  memset(&conn, 0, sizeof(conn));

#endif
