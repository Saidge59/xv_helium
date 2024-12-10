// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"
#include "mock_fake_dispatch.h"

// Module Under Test
#include "conn_service.h"

// Internal Dependencies (Not Mocked)
#include "util.h"
#include "key_hash_methods.h"

// Internal Mocks
#include "mock_conn_repo.h"
#include "mock_plugin_service.h"

// Third-Party Mocks
#include "mock_he.h"
#include "mock_statsd-client.h"
#include "mock_zlog.h"

TEST_FIXTURES();

void setUp(void) {
  FIXTURE_SERVER_CONN_SETUP();
}

void tearDown(void) {
  FIXTURE_SERVER_CONN_TEARDOWN();
}

void test_he_find_connection_none_found(void) {
  he_v4_ip_port_t test_value = {TEST_IP_ADDRESS, TEST_IP_PORT};

  bool update_source = false;
  ;

  he_server_connection_t *return_conn =
      he_find_connection(&server, NOT_FOUND_SESSION_ID, test_value, &update_source);

  TEST_ASSERT_NULL(return_conn);
  TEST_ASSERT_FALSE(update_source);
}

void test_he_find_connection_by_ip(void) {
  he_v4_ip_port_t test_value = {TEST_IP_ADDRESS, TEST_IP_PORT};
  ip_port_connection_map_set(&server.connections_by_external_ip_and_port, test_value, &conn);
  // Technically we don't get to this hashmap but want to ensure consistency
  session_connection_map_set(&server.connections_by_session, FOUND_SESSION_ID, &conn);

  bool update_source = false;

  he_server_connection_t *return_conn =
      he_find_connection(&server, FOUND_SESSION_ID, test_value, &update_source);

  TEST_ASSERT_EQUAL_PTR(&conn, return_conn);
  TEST_ASSERT_FALSE(update_source);
}

void test_he_find_connection_by_session(void) {
  he_v4_ip_port_t test_value = {TEST_IP_ADDRESS, TEST_IP_PORT};
  session_connection_map_set(&server.connections_by_session, FOUND_SESSION_ID, &conn);

  bool update_source = false;

  EXPECT_STATSD_INC("recovered_session");

  he_server_connection_t *return_conn =
      he_find_connection(&server, FOUND_SESSION_ID, test_value, &update_source);

  TEST_ASSERT_EQUAL_PTR(&conn, return_conn);
  TEST_ASSERT_TRUE(update_source);
}

void test_he_find_connection_by_session_port_scatter(void) {
  he_v4_ip_port_t test_value = {TEST_IP_ADDRESS, TEST_IP_PORT};
  session_connection_map_set(&server.connections_by_session, FOUND_SESSION_ID, &conn);

  // If port scatter is enabled, don't increment "recovered_session" count
  server.port_scatter = true;

  bool update_source = false;

  he_server_connection_t *return_conn =
      he_find_connection(&server, FOUND_SESSION_ID, test_value, &update_source);

  TEST_ASSERT_EQUAL_PTR(&conn, return_conn);
  TEST_ASSERT_TRUE(update_source);
}

void test_disconnect_all_connections(void) {
  // Add multiple connections to the map
  he_server_connection_t connections[100] = {0};
  for(size_t i = 0; i < sizeof(connections) / sizeof(connections[0]); i++) {
    he_server_connection_t *tmp = &connections[i];
    tmp->he_conn = (he_conn_t *)(0xdeadbeef + i);
    session_connection_map_set(&server.connections_by_session, FOUND_SESSION_ID + i, tmp);
    he_conn_disconnect_ExpectAndReturn(tmp->he_conn, HE_SUCCESS);
  }
  TEST_ASSERT_EQUAL(100, session_connection_map_count(&server.connections_by_session));

  he_disconnect_all_connections(&server);
  TEST_ASSERT_EQUAL(0, session_connection_map_count(&server.connections_by_session));
}

void test_disconnect_all_no_connection(void) {
  // Call disconnect all when there's no connection in the map
  he_disconnect_all_connections(&server);
  TEST_ASSERT_EQUAL(0, session_connection_map_count(&server.connections_by_session));
}

void test_change_of_address(void) {
  // All we're testing here is coordination
  struct sockaddr addr;
  he_v4_ip_port_t test_value = {TEST_IP_ADDRESS, TEST_IP_PORT};

  he_begin_session_id_rotation_Expect(&conn);
  he_update_connection_address_Expect(&conn, &addr, test_value);

  he_connection_change_of_address(&conn, &addr, test_value);
}

void test_disconnect_conn_success(void) {
  he_conn_disconnect_ExpectAndReturn(conn.he_conn, HE_SUCCESS);

  he_connection_disconnect(&conn);
}

void test_disconnect_conn_cleans_up_on_he_failure(void) {
  he_conn_disconnect_ExpectAndReturn(conn.he_conn, HE_ERR_INVALID_CONN_STATE);

  he_post_disconnect_cleanup_Expect(&conn);

  he_connection_disconnect(&conn);
}
