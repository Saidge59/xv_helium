// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"

// Module Under Test
#include "plugin_service.h"

// Third-Party Mocks
#include "mock_he.h"
#include "mock_obfuscation_engine.h"

TEST_FIXTURES();

he_plugin_chain_t plugins;

#define TEST_FM_SERVER "bobdolelives"
#define TEST_FM_INPUT "6 1 150 3 0 9 0 8 0 0 0 0 0 0"

void setUp(void) {
  FIXTURE_SERVER_SETUP();
}

void tearDown(void) {
  FIXTURE_SERVER_TEARDOWN();
}

void test_plugin_service_does_nothing_without_fm_values(void) {
  he_plugin_init_start(&server);
}

void test_plugin_service_init_creates_plugins_for_udp(void) {
  server.obfuscation_id = 2048;
  server.fm_server = TEST_FM_SERVER;
  server.fm_input = TEST_FM_INPUT;

  he_plugin_create_chain_ExpectAndReturn(&plugins);
  xvpn_obf_engine_plugin_Expect(NULL, server.fm_input, server.fm_server, true);
  xvpn_obf_engine_plugin_IgnoreArg_plugin();
  he_plugin_register_plugin_ExpectAnyArgsAndReturn(HE_SUCCESS);

  he_plugin_init_start(&server);

  // Cleanup used memory
  xvpn_obf_engine_plugin_free_Expect(server.udp_recv_plugin_set.fm_plugin);
  he_plugin_destroy_chain_Expect(&plugins);

  he_plugin_stop(&server);
}

void test_plugin_service_init_does_nothing_for_tcp_plugins(void) {
  server.obfuscation_id = 2048;
  server.fm_server = TEST_FM_SERVER;
  server.fm_input = TEST_FM_INPUT;
  server.connection_type = HE_CONNECTION_TYPE_STREAM;

  he_plugin_init_start(&server);
}

void test_plugin_service_creates_plugin_for_tcp(void) {
  server.obfuscation_id = 2048;
  server.fm_server = TEST_FM_SERVER;
  server.fm_input = TEST_FM_INPUT;
  server.connection_type = HE_CONNECTION_TYPE_STREAM;

  he_plugin_create_chain_ExpectAndReturn(&plugins);
  xvpn_obf_engine_plugin_Expect(NULL, server.fm_input, server.fm_server, true);
  xvpn_obf_engine_plugin_IgnoreArg_plugin();
  he_plugin_register_plugin_ExpectAnyArgsAndReturn(HE_SUCCESS);

  he_plugin_set_t ps = {0};
  he_init_plugin_set(&server, &ps);
  TEST_ASSERT_NOT_NULL(ps.fm_plugin);
  TEST_ASSERT_EQUAL(&plugins, ps.plugin_chain);

  // Cleanup used memory
  xvpn_obf_engine_plugin_free_Expect(ps.fm_plugin);
  he_plugin_destroy_chain_Expect(&plugins);
  he_free_plugin_set(&ps);
}

void test_plugin_service_does_nothing_without_fm_input(void) {
  server.fm_server = TEST_FM_SERVER;
  he_plugin_set_t ps = {0};
  he_init_plugin_set(&server, &ps);

  TEST_ASSERT_NULL(ps.fm_plugin);
  TEST_ASSERT_NULL(ps.plugin_chain);
}

void test_plugin_service_does_nothing_with_empty_fm_input(void) {
  server.fm_server = TEST_FM_SERVER;
  server.fm_input = "";
  he_plugin_set_t ps = {0};
  he_init_plugin_set(&server, &ps);

  TEST_ASSERT_NULL(ps.fm_plugin);
  TEST_ASSERT_NULL(ps.plugin_chain);
}

void test_plugin_service_does_nothing_with_empty_fm_server(void) {
  server.fm_server = "";
  server.fm_input = TEST_FM_INPUT;
  he_plugin_set_t ps = {0};
  he_init_plugin_set(&server, &ps);

  TEST_ASSERT_NULL(ps.fm_plugin);
  TEST_ASSERT_NULL(ps.plugin_chain);
}

void test_plugin_service_does_nothing_with_fm2(void) {
  server.obfuscation_id = 4096;
  server.fm_server = TEST_FM_SERVER;
  server.fm_input = TEST_FM_INPUT;
  he_plugin_set_t ps = {0};
  he_init_plugin_set(&server, &ps);

  TEST_ASSERT_NULL(ps.fm_plugin);
  TEST_ASSERT_NULL(ps.plugin_chain);
}
