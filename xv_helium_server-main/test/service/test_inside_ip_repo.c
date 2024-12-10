// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"
#include "lua_setup.h"

// Module Under Test
#include "inside_ip_repo.h"

// Internal Dependencies (Not Mocked)
#include "key_hash_methods.h"
#include "network.h"
#include "util.h"
#include "statistics.h"

// Third-Party Mocks
#include "mock_statsd-client.h"
#include "mock_zlog.h"

TEST_FIXTURES();

void setUp(void) {
  // Ignore logging.
  zlogf_time_Ignore();
  zlog_finish_Ignore();

  FIXTURE_SERVER_CONN_SETUP();

  lua_setup(&server);
}

void tearDown(void) {
  lua_teardown(&server);
  FIXTURE_SERVER_TEARDOWN();
}

void test_he_assign_release_inside_repo_success(void) {
  uint32_t test_ip = ip2int("10.125.255.254");
  he_assign_inside_ip(&conn);

  TEST_ASSERT_EQUAL(test_ip, conn.inside_ip);

  he_server_connection_t *test_conn = NULL;

  ip_connection_map_find(&server.connections_by_inside_ip, test_ip, &test_conn);

  TEST_ASSERT_EQUAL_PTR(&conn, test_conn);

  // Now we test release

  he_release_inside_ip(&conn);

  TEST_ASSERT_EQUAL(0, conn.inside_ip);

  test_conn = NULL;

  ip_connection_map_find(&server.connections_by_inside_ip, test_ip, &test_conn);

  TEST_ASSERT_EQUAL_PTR(NULL, test_conn);
};

void test_he_assign_all_the_ips(void) {
  for(int i = 0; i < 65534; i++) {
    int res = he_assign_inside_ip(&conn);
    TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  }

  int res = he_assign_inside_ip(&conn);
  TEST_ASSERT_EQUAL(HE_ERR_ACCESS_DENIED, res);

  he_release_inside_ip(&conn);

  res = he_assign_inside_ip(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void assert_dip_free_ip_pool_sizes(lua_State *L, int p202, int p203, int p204) {
  TEST_ASSERT_EQUAL(LUA_TTABLE, lua_getglobal(L, "free_dip_internal_ips"));

  TEST_ASSERT_EQUAL(LUA_TTABLE, lua_geti(L, -1, ip2int("192.168.220.202")));
  TEST_ASSERT_EQUAL(p202, lua_rawlen(L, -1));
  lua_pop(L, 1);

  TEST_ASSERT_EQUAL(LUA_TTABLE, lua_geti(L, -1, ip2int("192.168.220.203")));
  TEST_ASSERT_EQUAL(p203, lua_rawlen(L, -1));
  lua_pop(L, 1);

  TEST_ASSERT_EQUAL(LUA_TTABLE, lua_geti(L, -1, ip2int("192.168.220.204")));
  TEST_ASSERT_EQUAL(p204, lua_rawlen(L, -1));
  lua_pop(L, 1);

  lua_pop(L, 1);
}

void test_he_assign_release_dip_inside_repo_success(void) {
  server.is_dip_enabled = true;
  server.dip_ip_allocation_script = "lua/he_dip_ip_allocation.lua";
  lua_setup_dip(&server);
  conn.dip_addr.sin_addr.s_addr = ip2int("192.168.220.202");

  uint32_t test_ip = ip2int("10.125.0.31");

  he_assign_inside_ip(&conn);

  TEST_ASSERT_EQUAL(test_ip, conn.inside_ip);

  assert_dip_free_ip_pool_sizes(server.L, 15, 16, 16);

  he_server_connection_t *test_conn = NULL;

  ip_connection_map_find(&server.connections_by_inside_ip, test_ip, &test_conn);

  TEST_ASSERT_EQUAL_PTR(&conn, test_conn);

  // Now we test release

  he_release_inside_ip(&conn);

  TEST_ASSERT_EQUAL(0, conn.inside_ip);

  assert_dip_free_ip_pool_sizes(server.L, 16, 16, 16);

  test_conn = NULL;

  ip_connection_map_find(&server.connections_by_inside_ip, test_ip, &test_conn);

  TEST_ASSERT_EQUAL_PTR(NULL, test_conn);
}

void test_he_dip_assign_all_the_ips(void) {
  server.is_dip_enabled = true;
  server.dip_ip_allocation_script = "lua/he_dip_ip_allocation.lua";
  lua_setup_dip(&server);
  conn.dip_addr.sin_addr.s_addr = ip2int("192.168.220.202");

  for(int i = 0; i < 16; i++) {
    int res = he_assign_inside_ip(&conn);
    TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  }

  int res = he_assign_inside_ip(&conn);
  TEST_ASSERT_EQUAL(HE_ERR_ACCESS_DENIED, res);

  he_release_inside_ip(&conn);

  res = he_assign_inside_ip(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}
