// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"

// Module Under Test
#include "he_service.h"

// Internal Dependencies (Not Mocked)
#include "util.h"
#include "statistics.h"

// Internal Mocks
#include "mock_client_activities.h"
#include "mock_conn_repo.h"
#include "mock_inside_ip_repo.h"
#include "mock_user_repo.h"

// Third-Party Dependencies (Not Mocked)
#include <msgpack.h>

// Third-Party Mocks
#include "mock_he.h"
#include "mock_statsd-client.h"
#include "mock_zlog.h"

#define GOOD_USERNAME "success"
#define GOOD_PASSWORD "succ3ss"

#define FAIL_USERNAME "failure"
#define FAIL_PASSWORD "f4ilur3"

#define GOOD_AUTH_TOKEN "good_token_succeeds"
#define BAD_AUTH_TOKEN "bad_token_fails"

#define CLIENT_PLATFORM_ID "android"

TEST_FIXTURES();
msgpack_sbuffer sbuf = {0};
msgpack_packer pk;

void setUp(void) {
  FIXTURE_SERVER_CONN_SETUP();
  // Ignore all zlog calls in these tests
  zlogf_time_Ignore();
  msgpack_sbuffer_init(&sbuf);
  msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
}

void tearDown(void) {
  FIXTURE_SERVER_CONN_TEARDOWN();

  msgpack_sbuffer_destroy(&sbuf);
}

#define OPTIONALLY_POPULATE_STRING_VALUE(key, val) \
  if(val) {                                        \
    msgpack_pack_str(&pk, strlen(key));            \
    msgpack_pack_str_body(&pk, key, strlen(key));  \
    msgpack_pack_str(&pk, strlen(val));            \
    msgpack_pack_str_body(&pk, val, strlen(val));  \
  }

#define OPTIONALLY_POPULATE_UINT_VALUE(key, val)  \
  if(val) {                                       \
    msgpack_pack_str(&pk, strlen(key));           \
    msgpack_pack_str_body(&pk, key, strlen(key)); \
    msgpack_pack_uint64(&pk, val);                \
  }

// We use uint64_t here so that we can test overflow values for the actual uint8_t version numbers
static void pop_map_with_values(char *username, char *password, char *client_platform_id,
                                uint64_t major_version, uint64_t minor_version) {
  int count = (username && 1) + (password && 1) + (client_platform_id && 1) + (major_version && 1) +
              (minor_version && 1);
  msgpack_pack_map(&pk, count);
  OPTIONALLY_POPULATE_STRING_VALUE("u", username);
  OPTIONALLY_POPULATE_STRING_VALUE("p", password);
  OPTIONALLY_POPULATE_STRING_VALUE("cp", client_platform_id);
  OPTIONALLY_POPULATE_UINT_VALUE("pM", major_version);
  OPTIONALLY_POPULATE_UINT_VALUE("pm", minor_version);
}

void test_msgpack_auth_succeeds_only_username_password(void) {
  /* serialize values into the buffer using msgpack_sbuffer_write callback function. */
  pop_map_with_values(GOOD_USERNAME, GOOD_PASSWORD, NULL, 0, 0);

  he_check_auth_ExpectAndReturn(conn.state, GOOD_USERNAME, GOOD_PASSWORD, true);
  he_assign_inside_ip_ExpectAndReturn(&conn, HE_SUCCESS);
  EXPECT_STATSD_INC(HE_METRIC_AUTH_SUCCESS_AUTH_BUF);

  bool res = auth_buf_cb(IGNORED_PARAMETER, AUTH_TYPE_BUF_MSGPACK, sbuf.data, sbuf.size, &conn);

  TEST_ASSERT_TRUE(res);

  TEST_ASSERT_EQUAL_STRING("", conn.client_platform_id);
  TEST_ASSERT_EQUAL_STRING(GOOD_USERNAME, conn.username);
}

void test_msgpack_auth_succeeds_and_sets_client_platform_id(void) {
  /* serialize values into the buffer using msgpack_sbuffer_write callback function. */
  pop_map_with_values(GOOD_USERNAME, GOOD_PASSWORD, CLIENT_PLATFORM_ID, 0, 0);

  he_check_auth_ExpectAndReturn(conn.state, GOOD_USERNAME, GOOD_PASSWORD, true);
  he_assign_inside_ip_ExpectAndReturn(&conn, HE_SUCCESS);
  EXPECT_STATSD_INC(HE_METRIC_AUTH_SUCCESS_AUTH_BUF);

  bool res = auth_buf_cb(IGNORED_PARAMETER, AUTH_TYPE_BUF_MSGPACK, sbuf.data, sbuf.size, &conn);
  TEST_ASSERT_TRUE(res);

  TEST_ASSERT_EQUAL_STRING(CLIENT_PLATFORM_ID, conn.client_platform_id);
  TEST_ASSERT_EQUAL_STRING(GOOD_USERNAME, conn.username);
}

void test_msgpack_auth_fails_bad_password(void) {
  /* serialize values into the buffer using msgpack_sbuffer_write callback function. */
  pop_map_with_values(FAIL_USERNAME, FAIL_PASSWORD, CLIENT_PLATFORM_ID, 0, 0);

  he_check_auth_ExpectAndReturn(conn.state, FAIL_USERNAME, FAIL_PASSWORD, false);
  EXPECT_STATSD_INC(HE_METRIC_ACCESS_DENIED);

  bool res = auth_buf_cb(NULL, AUTH_TYPE_BUF_MSGPACK, sbuf.data, sbuf.size, &conn);

  TEST_ASSERT_FALSE(res);

  TEST_ASSERT_EQUAL_STRING(CLIENT_PLATFORM_ID, conn.client_platform_id);
}

void test_msgpack_auth_fails_with_empty_buffer(void) {
  bool res = auth_buf_cb(IGNORED_PARAMETER, AUTH_TYPE_BUF_MSGPACK, sbuf.data, sbuf.size, &conn);
  TEST_ASSERT_FALSE(res);
}

void test_msgpack_auth_fails_with_garbage(void) {
  uint8_t junk_buffer[100] = {0};

  for(int i = 0; i < sizeof(junk_buffer); i++) {
    junk_buffer[i] = i;
  }

  bool res = auth_buf_cb(NULL, AUTH_TYPE_BUF_MSGPACK, junk_buffer, sizeof(junk_buffer), &conn);
  TEST_ASSERT_FALSE(res);
}

void test_msgpack_auth_fails_with_bad_type(void) {
  pop_map_with_values(GOOD_USERNAME, GOOD_PASSWORD, CLIENT_PLATFORM_ID, 0, 0);

  bool res = auth_buf_cb(IGNORED_PARAMETER, 42, sbuf.data, sbuf.size, &conn);
  TEST_ASSERT_FALSE(res);
}

void test_msgpack_auth_fails_with_empty_strings(void) {
  pop_map_with_values("", "", "", 0, 0);

  bool res = auth_buf_cb(NULL, 42, sbuf.data, sbuf.size, &conn);
  TEST_ASSERT_FALSE(res);
}

void test_msgpack_auth_succeeds_with_extra_keys(void) {
  /* serialize values into the buffer using msgpack_sbuffer_write callback function. */
  pop_map_with_values(GOOD_USERNAME, GOOD_PASSWORD, NULL, 0, 0);
  OPTIONALLY_POPULATE_STRING_VALUE("test", "extra_value");

  he_check_auth_ExpectAndReturn(conn.state, GOOD_USERNAME, GOOD_PASSWORD, true);
  he_assign_inside_ip_ExpectAndReturn(&conn, HE_SUCCESS);
  EXPECT_STATSD_INC(HE_METRIC_AUTH_SUCCESS_AUTH_BUF);

  bool res = auth_buf_cb(IGNORED_PARAMETER, AUTH_TYPE_BUF_MSGPACK, sbuf.data, sbuf.size, &conn);

  TEST_ASSERT_TRUE(res);

  TEST_ASSERT_EQUAL_STRING("", conn.client_platform_id);
  TEST_ASSERT_EQUAL_STRING(GOOD_USERNAME, conn.username);
}

void test_msgpack_auth_succeeds_and_sets_protocol(void) {
  /* serialize values into the buffer using msgpack_sbuffer_write callback function. */
  pop_map_with_values(GOOD_USERNAME, GOOD_PASSWORD, NULL, 1, 1);

  he_conn_set_protocol_version_ExpectAndReturn(conn.he_conn, 1, 1, HE_SUCCESS);

  he_check_auth_ExpectAndReturn(conn.state, GOOD_USERNAME, GOOD_PASSWORD, true);
  he_assign_inside_ip_ExpectAndReturn(&conn, HE_SUCCESS);
  EXPECT_STATSD_INC(HE_METRIC_AUTH_SUCCESS_AUTH_BUF);

  bool res = auth_buf_cb(IGNORED_PARAMETER, AUTH_TYPE_BUF_MSGPACK, sbuf.data, sbuf.size, &conn);

  TEST_ASSERT_TRUE(res);

  TEST_ASSERT_EQUAL_STRING("", conn.client_platform_id);
  TEST_ASSERT_EQUAL_STRING(GOOD_USERNAME, conn.username);
}

void test_msgpack_auth_succeeds_and_ignores_overflow_protocol(void) {
  /* serialize values into the buffer using msgpack_sbuffer_write callback function. */
  pop_map_with_values(GOOD_USERNAME, GOOD_PASSWORD, NULL, 64329, 3023942);

  he_check_auth_ExpectAndReturn(conn.state, GOOD_USERNAME, GOOD_PASSWORD, true);
  he_assign_inside_ip_ExpectAndReturn(&conn, HE_SUCCESS);
  EXPECT_STATSD_INC(HE_METRIC_AUTH_SUCCESS_AUTH_BUF);

  bool res = auth_buf_cb(IGNORED_PARAMETER, AUTH_TYPE_BUF_MSGPACK, sbuf.data, sbuf.size, &conn);

  TEST_ASSERT_TRUE(res);

  TEST_ASSERT_EQUAL_STRING("", conn.client_platform_id);
  TEST_ASSERT_EQUAL_STRING(GOOD_USERNAME, conn.username);
}

void test_userpass_auth_succeeds(void) {
  he_check_auth_ExpectAndReturn(conn.state, GOOD_USERNAME, GOOD_PASSWORD, true);
  he_assign_inside_ip_ExpectAndReturn(&conn, HE_SUCCESS);
  EXPECT_STATSD_INC(HE_METRIC_AUTH_SUCCESS_USER_PASS);

  bool res = auth_cb(IGNORED_PARAMETER, GOOD_USERNAME, GOOD_PASSWORD, &conn);

  TEST_ASSERT_TRUE(res);
  TEST_ASSERT_EQUAL_STRING(GOOD_USERNAME, conn.username);
}

void test_userpass_fails(void) {
  he_check_auth_ExpectAndReturn(conn.state, FAIL_USERNAME, FAIL_PASSWORD, false);
  EXPECT_STATSD_INC(HE_METRIC_ACCESS_DENIED);

  bool res = auth_cb(IGNORED_PARAMETER, FAIL_USERNAME, FAIL_PASSWORD, &conn);

  TEST_ASSERT_FALSE(res);
}

void test_auth_token_cb_succeeds(void) {
  he_check_auth_token_ExpectAndReturn(&conn, GOOD_AUTH_TOKEN, strlen(GOOD_AUTH_TOKEN), true);
  he_conn_set_protocol_version_ExpectAndReturn(conn.he_conn, 1, 2, HE_SUCCESS);
  he_assign_inside_ip_ExpectAndReturn(&conn, HE_SUCCESS);
  EXPECT_STATSD_INC(HE_METRIC_AUTH_SUCCESS_AUTH_TOKEN);

  bool res = auth_token_cb(IGNORED_PARAMETER, GOOD_AUTH_TOKEN, strlen(GOOD_AUTH_TOKEN), &conn);

  TEST_ASSERT_TRUE(res);
  TEST_ASSERT_EQUAL_STRING("", conn.username);
}

void test_auth_token_cb_fails(void) {
  he_check_auth_token_ExpectAndReturn(&conn, BAD_AUTH_TOKEN, strlen(BAD_AUTH_TOKEN), false);
  EXPECT_STATSD_INC(HE_METRIC_ACCESS_DENIED);

  bool res = auth_token_cb(IGNORED_PARAMETER, BAD_AUTH_TOKEN, strlen(BAD_AUTH_TOKEN), &conn);

  TEST_ASSERT_FALSE(res);
}

void test_auth_token_assign_inside_ip_fails(void) {
  he_check_auth_token_ExpectAndReturn(&conn, GOOD_AUTH_TOKEN, strlen(GOOD_AUTH_TOKEN), true);
  he_conn_set_protocol_version_ExpectAndReturn(conn.he_conn, 1, 2, HE_SUCCESS);
  he_assign_inside_ip_ExpectAndReturn(&conn, HE_ERR_ACCESS_DENIED);
  EXPECT_STATSD_INC(HE_METRIC_ASSIGN_INSIDE_IP_ERROR);

  bool res = auth_token_cb(IGNORED_PARAMETER, GOOD_AUTH_TOKEN, strlen(GOOD_AUTH_TOKEN), &conn);

  TEST_ASSERT_FALSE(res);
}

void test_userpass_fails_nulls(void) {
  he_check_auth_ExpectAndReturn(conn.state, NULL, NULL, false);
  EXPECT_STATSD_INC(HE_METRIC_ACCESS_DENIED);

  bool res = auth_cb(IGNORED_PARAMETER, NULL, NULL, &conn);

  TEST_ASSERT_FALSE(res);
}

void test_server_event_cb_secure_renegotiation_start(void) {
  EXPECT_STATSD_INC(HE_METRIC_RENEGOTIATION_STARTED);

  server_event_cb(IGNORED_PARAMETER, HE_EVENT_SECURE_RENEGOTIATION_STARTED, &conn);
}

void test_server_event_cb_secure_renegotiation_finish(void) {
  EXPECT_STATSD_INC(HE_METRIC_RENEGOTIATION_COMPLETED);

  server_event_cb(IGNORED_PARAMETER, HE_EVENT_SECURE_RENEGOTIATION_COMPLETED, &conn);
}

void test_server_event_cb_rotation_acked(void) {
  he_finalize_session_id_rotation_Expect(&conn);

  server_event_cb(IGNORED_PARAMETER, HE_EVENT_PENDING_SESSION_ACKNOWLEDGED, &conn);
}

void test_server_event_cb_non_existent_event(void) {
  server_event_cb(IGNORED_PARAMETER, 424242, &conn);
}

void test_state_change_cb_link_up(void) {
  EXPECT_STATSD_TIMING("to_link_up_time");

  he_conn_t *he_conn = (he_conn_t *)(uintptr_t)0xdeadbeef;
  he_conn_get_current_cipher_ExpectAndReturn(he_conn, "mycipher");
  he_conn_get_curve_name_ExpectAndReturn(he_conn, "lolcurve");
  he_conn_get_current_protocol_ExpectAndReturn(he_conn, HE_CONNECTION_PROTOCOL_TLS_1_3);
  he_conn_get_session_id_ExpectAndReturn(he_conn, 0xdddddddd);

  EXPECT_STATSD_INC("link_up_with_aes");
  EXPECT_STATSD_INC(HE_METRIC_LINK_UP_TLS_1_3);
  EXPECT_STATSD_INC(HE_METRIC_LINK_UP_ECC);

  state_change_cb(he_conn, HE_STATE_LINK_UP, &conn);
}

void test_state_change_cb_link_up_with_chacha20(void) {
  EXPECT_STATSD_TIMING("to_link_up_time");

  he_conn_t *he_conn = (he_conn_t *)(uintptr_t)0xdeadbeef;
  he_conn_get_current_cipher_ExpectAndReturn(he_conn,
                                             "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
  he_conn_get_curve_name_ExpectAndReturn(he_conn, "P256_KYBER_LEVEL1");
  he_conn_get_current_protocol_ExpectAndReturn(he_conn, HE_CONNECTION_PROTOCOL_DTLS_1_3);
  he_conn_get_session_id_ExpectAndReturn(he_conn, 0xdddddddd);

  EXPECT_STATSD_INC("link_up_with_chacha20");
  EXPECT_STATSD_INC(HE_METRIC_LINK_UP_DTLS_1_3);
  EXPECT_STATSD_INC(HE_METRIC_LINK_UP_PQC);

  state_change_cb(he_conn, HE_STATE_LINK_UP, &conn);
}

void test_state_change_cb_link_up_with_chacha20_ml_kem(void) {
  EXPECT_STATSD_TIMING("to_link_up_time");

  he_conn_t *he_conn = (he_conn_t *)(uintptr_t)0xdeadbeef;
  he_conn_get_current_cipher_ExpectAndReturn(he_conn,
                                             "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
  he_conn_get_curve_name_ExpectAndReturn(he_conn, "P521_ML_KEM_1024");
  he_conn_get_current_protocol_ExpectAndReturn(he_conn, HE_CONNECTION_PROTOCOL_DTLS_1_3);
  he_conn_get_session_id_ExpectAndReturn(he_conn, 0xdddddddd);

  EXPECT_STATSD_INC("link_up_with_chacha20");
  EXPECT_STATSD_INC(HE_METRIC_LINK_UP_DTLS_1_3);
  EXPECT_STATSD_INC(HE_METRIC_LINK_UP_PQC_ML_KEM);

  state_change_cb(he_conn, HE_STATE_LINK_UP, &conn);
}

void test_state_change_cb_link_up_unknown_curve(void) {
  EXPECT_STATSD_TIMING("to_link_up_time");

  he_conn_t *he_conn = (he_conn_t *)(uintptr_t)0xdeadbeef;
  he_conn_get_current_cipher_ExpectAndReturn(he_conn, "mycipher");
  he_conn_get_curve_name_ExpectAndReturn(he_conn, NULL);
  he_conn_get_current_protocol_ExpectAndReturn(he_conn, HE_CONNECTION_PROTOCOL_TLS_1_3);
  he_conn_get_session_id_ExpectAndReturn(he_conn, 0xdddddddd);

  EXPECT_STATSD_INC("link_up_with_aes");
  EXPECT_STATSD_INC(HE_METRIC_LINK_UP_TLS_1_3);
  EXPECT_STATSD_INC(HE_METRIC_LINK_UP_UNKNOWN_KEM);

  state_change_cb(he_conn, HE_STATE_LINK_UP, &conn);
}

static uint8_t protocol_major_version = 0;
static uint8_t protocol_minor_version = 0;
static he_return_code_t stub_he_conn_get_protocol_version(he_conn_t *conn, uint8_t *major_version,
                                                          uint8_t *minor_version,
                                                          int cmock_num_calls) {
  *major_version = protocol_major_version;
  *minor_version = protocol_minor_version;
  return HE_SUCCESS;
}
void test_state_change_cb_online(void) {
  he_schedule_client_activity_ExpectAndReturn(&conn, HE_SUCCESS);
  EXPECT_STATSD_TIMING("to_online_time");

  // Stub the he_conn_get_protocol_version to return version 1.2
  protocol_major_version = 1;
  protocol_minor_version = 2;
  he_conn_get_protocol_version_Stub(stub_he_conn_get_protocol_version);

  he_connection_start_renegotiation_timer_Expect(&conn);
  EXPECT_STATSD_INC(HE_METRIC_ONLINE_WITH_PROTOCOL_V1_2);

  state_change_cb(IGNORED_PARAMETER, HE_STATE_ONLINE, &conn);
}

void test_state_change_cb_disconnected(void) {
  he_post_disconnect_cleanup_Expect(&conn);

  state_change_cb(IGNORED_PARAMETER, HE_STATE_DISCONNECTED, &conn);
}

void test_state_change_cb_random_state(void) {
  state_change_cb(IGNORED_PARAMETER, 424242, &conn);
}

void test_state_change_cb_port_scatter(void) {
  EXPECT_STATSD_TIMING("to_link_up_time");

  he_conn_t *he_conn = (he_conn_t *)(uintptr_t)0xdeadbeef;

  // If port scatter is enabled,
  // state_change_cb should send port scatter server config on LINK_UP
  conn.state->port_scatter = true;
  conn.state->port_scatter_ports[0] = 443;
  conn.state->port_scatter_ports[1] = 22;
  conn.state->port_scatter_ports[2] = 61024;

  // Expect he_conn_send_server_config is called 3 times
  for(size_t i = 0; i < 3; i++) {
    he_conn_send_server_config_ExpectAndReturn(he_conn, NULL, 0, HE_SUCCESS);
    he_conn_send_server_config_IgnoreArg_buffer();
    he_conn_send_server_config_IgnoreArg_length();
  }

  he_conn_get_current_cipher_ExpectAndReturn(he_conn, "mycipher");
  he_conn_get_curve_name_ExpectAndReturn(he_conn, "lolcurve");
  he_conn_get_current_protocol_ExpectAndReturn(he_conn, HE_CONNECTION_PROTOCOL_DTLS_1_2);
  he_conn_get_session_id_ExpectAndReturn(he_conn, 0xdddddddd);

  EXPECT_STATSD_INC("link_up_with_aes");
  EXPECT_STATSD_INC(HE_METRIC_LINK_UP_DTLS_1_2);
  EXPECT_STATSD_INC(HE_METRIC_LINK_UP_ECC);

  state_change_cb(he_conn, HE_STATE_LINK_UP, &conn);
}

void test_create_port_scatter_config(void) {
  uint8_t buf[1500] = {0};
  uint16_t buflen = sizeof(buf);
  uint16_t outlen = 0;

  // Do nothing if state is NULL or port scatter is not enabled
  he_internal_create_port_scatter_config(NULL, buf, buflen, &outlen);
  TEST_ASSERT_EQUAL(0, outlen);
  he_internal_create_port_scatter_config(&server, buf, buflen, &outlen);
  TEST_ASSERT_EQUAL(0, outlen);

  // Do nothing if there's zero port scatter port
  server.port_scatter = true;
  he_internal_create_port_scatter_config(&server, buf, buflen, &outlen);
  TEST_ASSERT_EQUAL(0, outlen);

  // There are valid port scatter ports
  server.port_scatter_ports[0] = 443;
  server.port_scatter_ports[1] = 22;
  server.port_scatter_ports[2] = 9999;
  he_internal_create_port_scatter_config(&server, buf, buflen, &outlen);

  uint8_t expect[1500] = {
      0x82, 0xb2, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x73, 0x63, 0x61, 0x74, 0x74,
      0x65, 0x72, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x03, 0xb2, 0x70, 0x6f,
      0x72, 0x74, 0x5f, 0x73, 0x63, 0x61, 0x74, 0x74, 0x65, 0x72, 0x5f, 0x70,
      0x6f, 0x72, 0x74, 0x73, 0x93, 0xcd, 0x01, 0xbb, 0x16, 0xcd, 0x27, 0x0f,
  };
  TEST_ASSERT_EQUAL(48, outlen);
  TEST_ASSERT_EQUAL_MEMORY(expect, buf, outlen);
}
