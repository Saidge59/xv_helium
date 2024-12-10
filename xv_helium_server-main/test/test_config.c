// Test Requirements
#include "he_test_definitions.h"
#include "unity.h"

// Module Under Test
#include "state.h"

// Internal Dependencies (Not Mocked)
#include "key_hash_methods.h"
#include "util.h"

// Internal Mocks
#include "mock_conn_repo.h"
#include "mock_conn_service.h"
#include "mock_he_service.h"
#include "mock_hpt_adapter.h"
#include "mock_inside_ip_repo.h"
#include "mock_plugin_service.h"
#include "mock_statistics.h"
#include "mock_tcp_adapter.h"
#include "mock_tun_adapter.h"
#include "mock_udp_adapter.h"
#include "mock_user_repo.h"

// Third-Party Mocks
#include "mock_he.h"
#include "mock_uv.h"
#include "mock_zlog.h"

static he_server_t server = {0};

void setUp(void) {
  // Ignore all zlog calls in these tests
  zlogf_time_Ignore();
  zlog_flush_buffer_Ignore();
  zlog_finish_Ignore();

  // Reset server state
  memset(&server, 0, sizeof(he_server_t));
}

void tearDown(void) {
  he_state_cleanup(&server);
}

void test_state_load_config_udp(void) {
  zlogf_time_Ignore();
  zlog_finish_Ignore();

  server.config_file = "./test/support/test_server.conf",

  he_lua_init(&server);
  he_state_load_config(&server);

  TEST_ASSERT_EQUAL(HE_CONNECTION_TYPE_DATAGRAM, server.connection_type);

  TEST_ASSERT_EQUAL(19655, server.bind_port);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", server.bind_ip);
  TEST_ASSERT_EQUAL_STRING("185.198.242.5", server.peer_ip);
  TEST_ASSERT_EQUAL_STRING("185.198.242.6", server.client_ip);
  TEST_ASSERT_EQUAL_STRING("8.8.8.8", server.dns_ip);
  TEST_ASSERT_EQUAL_STRING("./test/support/server.crt", server.server_cert);
  TEST_ASSERT_EQUAL_STRING("./test/support/server.key", server.server_key);

  TEST_ASSERT_EQUAL_MESSAGE(0, server.obfuscation_id,
                            "obfuscation_id should be 0 if it doesn't exist in the config");
  TEST_ASSERT_NULL(server.fm_server);
  TEST_ASSERT_NULL(server.fm_input);
  TEST_ASSERT_EQUAL_STRING("instance:docker-test,fm_input:none,", server.statsd_tags);

  TEST_ASSERT_EQUAL_STRING("lua/he_auth.lua", server.auth_script);
  TEST_ASSERT_EQUAL_STRING("./test/support/test_db.sqlite3", server.auth_path);
  TEST_ASSERT_EQUAL_STRING("lua/he_auth_token.lua", server.auth_token_script);
  TEST_ASSERT_EQUAL_STRING("lua/support/auth_token.json", server.auth_token_config);
}

void test_state_load_config_tcp(void) {
  zlogf_time_Ignore();
  zlog_finish_Ignore();

  server.config_file = "./test/support/tcp_test_server.conf",

  he_lua_init(&server);
  he_state_load_config(&server);

  TEST_ASSERT_EQUAL(HE_CONNECTION_TYPE_STREAM, server.connection_type);

  TEST_ASSERT_EQUAL(19656, server.bind_port);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", server.bind_ip);
  TEST_ASSERT_EQUAL_STRING("185.198.242.5", server.peer_ip);
  TEST_ASSERT_EQUAL_STRING("185.198.242.6", server.client_ip);
  TEST_ASSERT_EQUAL_STRING("8.8.8.8", server.dns_ip);
  TEST_ASSERT_EQUAL_STRING("./test/support/server.crt", server.server_cert);
  TEST_ASSERT_EQUAL_STRING("./test/support/server.key", server.server_key);

  TEST_ASSERT_EQUAL_MESSAGE(0, server.obfuscation_id,
                            "obfuscation_id should be 0 if it doesn't exist in the config");
  TEST_ASSERT_NULL(server.fm_server);
  TEST_ASSERT_NULL(server.fm_input);
  TEST_ASSERT_EQUAL_STRING("instance:docker-test,fm_input:none,", server.statsd_tags);

  TEST_ASSERT_EQUAL_STRING("lua/he_auth.lua", server.auth_script);
  TEST_ASSERT_EQUAL_STRING("./test/support/test_db.sqlite3", server.auth_path);
  TEST_ASSERT_EQUAL_STRING("lua/he_auth_token.lua", server.auth_token_script);
  TEST_ASSERT_EQUAL_STRING("lua/support/auth_token.json", server.auth_token_config);

  TEST_ASSERT_NULL(server.dip_ip_allocation_script);
  TEST_ASSERT_NULL(server.dip_internal_ip_map);

  TEST_ASSERT_EQUAL(false, server.is_dip_enabled);
}

void test_state_load_config_dip(void) {
  zlogf_time_Ignore();
  zlog_finish_Ignore();

  server.config_file = "./test/support/test_server_dip.conf",

  he_lua_init(&server);
  he_state_load_config(&server);

  TEST_ASSERT_EQUAL(HE_CONNECTION_TYPE_DATAGRAM, server.connection_type);

  TEST_ASSERT_EQUAL(19655, server.bind_port);
  TEST_ASSERT_EQUAL_STRING("1.2.3.4", server.bind_ip);
  TEST_ASSERT_EQUAL_STRING("185.198.242.5", server.peer_ip);
  TEST_ASSERT_EQUAL_STRING("185.198.242.6", server.client_ip);
  TEST_ASSERT_EQUAL_STRING("8.8.8.8", server.dns_ip);
  TEST_ASSERT_EQUAL_STRING("./test/support/server.crt", server.server_cert);
  TEST_ASSERT_EQUAL_STRING("./test/support/server.key", server.server_key);

  TEST_ASSERT_EQUAL_MESSAGE(0, server.obfuscation_id,
                            "obfuscation_id should be 0 if it doesn't exist in the config");
  TEST_ASSERT_NULL(server.fm_server);
  TEST_ASSERT_NULL(server.fm_input);
  TEST_ASSERT_EQUAL_STRING("instance:docker-test,fm_input:none,", server.statsd_tags);

  TEST_ASSERT_EQUAL_STRING("lua/he_auth.lua", server.auth_script);
  TEST_ASSERT_EQUAL_STRING("/dev/null", server.auth_path);
  TEST_ASSERT_EQUAL_STRING("lua/he_auth_token.lua", server.auth_token_script);
  TEST_ASSERT_EQUAL_STRING("lua/support/auth_token_dip.json", server.auth_token_config);

  TEST_ASSERT_EQUAL_STRING("lua/he_dip_ip_allocation.lua", server.dip_ip_allocation_script);
  TEST_ASSERT_EQUAL_STRING("lua/support/dip_internal_ip_map.json", server.dip_internal_ip_map);

  TEST_ASSERT_EQUAL(true, server.is_dip_enabled);
}

void test_state_load_config_obfs_no_obfuscation_id(void) {
  zlogf_time_Ignore();
  zlog_finish_Ignore();

  server.config_file = "./test/support/obfs_noop.conf",

  he_lua_init(&server);
  he_state_load_config(&server);

  TEST_ASSERT_EQUAL(HE_CONNECTION_TYPE_STREAM, server.connection_type);

  TEST_ASSERT_EQUAL(19657, server.bind_port);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", server.bind_ip);
  TEST_ASSERT_EQUAL_STRING("185.198.242.5", server.peer_ip);
  TEST_ASSERT_EQUAL_STRING("185.198.242.6", server.client_ip);
  TEST_ASSERT_EQUAL_STRING("8.8.8.8", server.dns_ip);
  TEST_ASSERT_EQUAL_STRING("./test/support/server.crt", server.server_cert);
  TEST_ASSERT_EQUAL_STRING("./test/support/server.key", server.server_key);

  TEST_ASSERT_EQUAL(2048, server.obfuscation_id);
  TEST_ASSERT_EQUAL_STRING("bobdolelives", server.fm_server);
  TEST_ASSERT_EQUAL_STRING("0 0 0 0 0 0 0 0 0 0", server.fm_input);
  TEST_ASSERT_EQUAL_STRING("instance:docker-test,fm_input:0 0 0 0 0 0 0 0 0 0,",
                           server.statsd_tags);
}

void test_state_load_config_obfs_fm1(void) {
  zlogf_time_Ignore();
  zlog_finish_Ignore();

  server.config_file = "./test/support/obfs_fm1.conf",

  he_lua_init(&server);
  he_state_load_config(&server);

  TEST_ASSERT_EQUAL(HE_CONNECTION_TYPE_STREAM, server.connection_type);

  TEST_ASSERT_EQUAL(19657, server.bind_port);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", server.bind_ip);
  TEST_ASSERT_EQUAL_STRING("185.198.242.5", server.peer_ip);
  TEST_ASSERT_EQUAL_STRING("185.198.242.6", server.client_ip);
  TEST_ASSERT_EQUAL_STRING("8.8.8.8", server.dns_ip);
  TEST_ASSERT_EQUAL_STRING("./test/support/server.crt", server.server_cert);
  TEST_ASSERT_EQUAL_STRING("./test/support/server.key", server.server_key);

  TEST_ASSERT_EQUAL(2048, server.obfuscation_id);
  TEST_ASSERT_EQUAL_STRING("bobdolelives", server.fm_server);
  TEST_ASSERT_EQUAL_STRING("0 0 0 0 0 0 0 0 0 0", server.fm_input);
  TEST_ASSERT_EQUAL_STRING("instance:docker-test,fm_input:0 0 0 0 0 0 0 0 0 0,",
                           server.statsd_tags);
}

void test_state_load_config_obfs_fm2(void) {
  zlogf_time_Ignore();
  zlog_finish_Ignore();

  server.config_file = "./test/support/obfs_fm2.conf",

  he_lua_init(&server);
  he_state_load_config(&server);

  TEST_ASSERT_EQUAL(HE_CONNECTION_TYPE_STREAM, server.connection_type);

  TEST_ASSERT_EQUAL(19657, server.bind_port);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", server.bind_ip);
  TEST_ASSERT_EQUAL_STRING("185.198.242.5", server.peer_ip);
  TEST_ASSERT_EQUAL_STRING("185.198.242.6", server.client_ip);
  TEST_ASSERT_EQUAL_STRING("8.8.8.8", server.dns_ip);
  TEST_ASSERT_EQUAL_STRING("./test/support/server.crt", server.server_cert);
  TEST_ASSERT_EQUAL_STRING("./test/support/server.key", server.server_key);

  TEST_ASSERT_EQUAL(4096, server.obfuscation_id);
  TEST_ASSERT_EQUAL_STRING("bobdolelives", server.fm_server);
  TEST_ASSERT_EQUAL_STRING("01c0082261a92b9d0558e3857b7e4e00a192f97b0899f21e2c04fa58983d025f",
                           server.fm_input);
  TEST_ASSERT_EQUAL_STRING(
      "instance:docker-test,fm_input:"
      "01c0082261a92b9d0558e3857b7e4e00a192f97b0899f21e2c04fa58983d025f,",
      server.statsd_tags);
}
