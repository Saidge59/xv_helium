// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"

// Module Under Test
#include "client_activities.h"

// Internal Dependencies (Not Mocked)
#include "util.h"

// Third-Party Mocks
#include "mock_he.h"
#include "mock_statsd-client.h"
#include "mock_uv.h"
#include "mock_zlog.h"

TEST_FIXTURES();

const char *TEST_CLIENT_IP = "198.51.100.54";
const char *TEST_USERNAME = "abcdefg12345678hijklmnop";
const char *TEST_COMMON_NAME = "expressvpn_customer";

const char *TEST_SERVER_IP = "191.96.49.175";
const char *TEST_ASSIGNED_IP = "10.125.0.1";
const int TEST_SERVER_PORT = 48092;

uv_buf_t stateless_uv_buf_init_for_test(char *base, unsigned int len, int num_calls) {
  uv_buf_t temp_buf = {0};
  temp_buf.base = base;
  temp_buf.len = len;
  return temp_buf;
}

void setUp(void) {
  FIXTURE_SERVER_CONN_SETUP();
  zlogf_time_Ignore();
  zlog_flush_buffer_Ignore();
  uv_buf_init_Stub(stateless_uv_buf_init_for_test);

  conn.inside_ip = ip2int(TEST_ASSIGNED_IP);
  conn.external_ip_port.ip = ip2int(TEST_CLIENT_IP);

  // Fixture setup/teardown ensures rest of array is 0
  memcpy(conn.username, TEST_USERNAME, strlen(TEST_USERNAME));

  conn.state->bind_ip = TEST_SERVER_IP;
  conn.state->bind_port = TEST_SERVER_PORT;
  conn.state->ca_tpl = "/tmp/he_ca_XXXXXX";
}

void tearDown(void) {
  FIXTURE_SERVER_CONN_TEARDOWN();
}

/**
 * http://docs.libuv.org/en/v1.x/fs.html#c.uv_fs_mkstemp
 */
int stub_uv_fs_mkstemp(uv_loop_t *loop, uv_fs_t *req, const char *tpl, uv_fs_cb cb, int num_calls) {
  // Validate req->data
  TEST_ASSERT_NOT_NULL(req);

  he_client_activity_t *data = (he_client_activity_t *)req->data;

  TEST_ASSERT_NOT_NULL(data);

  TEST_ASSERT_EQUAL(data->state, conn.state);
  if(strlen(conn.client_platform_id) > 0) {
    TEST_ASSERT_EQUAL_STRING(
        "on_disconnect,198.51.100.54,abcdefg12345678hijklmnop,abcdefg12345678hijklmnop,191.96.49."
        "175,"
        "48092,test_client_platform,he-udp,0,2,0,0,0,10.125.0.1\n",

        data->buffer.base);
  } else {
    char expected_str[1024] = {0};
    sprintf(
        expected_str,
        "on_disconnect,198.51.100.54,abcdefg12345678hijklmnop,abcdefg12345678hijklmnop,191.96.49."
        "175,"
        "48092,unknown,he-udp,%d,2,0,0,0,10.125.0.1\n",
        data->state->obfuscation_id);
    TEST_ASSERT_EQUAL_STRING(expected_str, data->buffer.base);
  }

  TEST_ASSERT_EQUAL_STRING("/tmp/he_ca_XXXXXX", tpl);
  // This indicates that this is the first call, will fail the test if it's called again
  TEST_ASSERT_EQUAL(0, num_calls);

  cleanup_pointers(req);

  return 0;
}

int stub_uv_fs_close(uv_loop_t *loop, uv_fs_t *req, uv_file file, uv_fs_cb cb, int num_calls) {
  // Validate req->data
  TEST_ASSERT_NOT_NULL(req);

  he_client_activity_t *data = (he_client_activity_t *)req->data;

  TEST_ASSERT_NOT_NULL(data);

  TEST_ASSERT_EQUAL(42, file);

  // Only call once
  TEST_ASSERT_EQUAL(0, num_calls);

  return 0;
}

void test_he_schedule_client_activity(void) {
  uv_fs_mkstemp_Stub(stub_uv_fs_mkstemp);

  uv_fs_req_cleanup_ExpectAnyArgs();

  he_return_code_t ret = he_schedule_client_activity(&conn);

  TEST_ASSERT_EQUAL(ret, HE_SUCCESS);
}

void test_he_schedule_client_activity_dss_proxy(void) {
  conn.state->bind_ip = "fdc1:4db7:3c37:65a8::ffff:c000:0215";
  conn.tcp_is_proxied = true;

  struct sockaddr_in bind_addr = {0};
  bind_addr.sin_addr.s_addr = ip2int(TEST_SERVER_IP);
  bind_addr.sin_port = TEST_SERVER_PORT;
  conn.tcp_proxied_bind_ip_port = he_create_ipcombo_v4_from_addr((struct sockaddr *)&bind_addr);

  uv_fs_mkstemp_Stub(stub_uv_fs_mkstemp);

  uv_fs_req_cleanup_ExpectAnyArgs();

  he_return_code_t ret = he_schedule_client_activity(&conn);

  TEST_ASSERT_EQUAL(ret, HE_SUCCESS);
}

void test_he_schedule_client_activity_obfs(void) {
  conn.state->obfuscation_id = 2048;

  uv_fs_mkstemp_Stub(stub_uv_fs_mkstemp);

  uv_fs_req_cleanup_ExpectAnyArgs();

  he_return_code_t ret = he_schedule_client_activity(&conn);

  TEST_ASSERT_EQUAL(ret, HE_SUCCESS);
}

void test_he_schedule_client_activity_obfs_empty(void) {
  conn.state->fm_input = "";

  uv_fs_mkstemp_Stub(stub_uv_fs_mkstemp);

  uv_fs_req_cleanup_ExpectAnyArgs();

  he_return_code_t ret = he_schedule_client_activity(&conn);

  TEST_ASSERT_EQUAL(ret, HE_SUCCESS);
}

void test_he_schedule_client_activity_client_platform(void) {
  char *client_platform_id = "test_client_platform";
  memcpy(conn.client_platform_id, client_platform_id, strlen(client_platform_id) + 1);

  uv_fs_mkstemp_Stub(stub_uv_fs_mkstemp);

  uv_fs_req_cleanup_ExpectAnyArgs();

  he_return_code_t ret = he_schedule_client_activity(&conn);

  TEST_ASSERT_EQUAL(ret, HE_SUCCESS);
}

void test_he_schedule_client_activity_libuv_error(void) {
  uv_fs_mkstemp_ExpectAnyArgsAndReturn(-1);
  EXPECT_STATSD_INC("ca_error");
  uv_fs_req_cleanup_ExpectAnyArgs();

  he_return_code_t ret = he_schedule_client_activity(&conn);

  TEST_ASSERT_EQUAL(ret, HE_ERR_CALLBACK_FAILED);
}

void test_on_client_activity_mkstemp_bad_fd(void) {
  uv_fs_t *req = jecalloc(1, sizeof(uv_fs_t));
  he_client_activity_t *ca = jecalloc(1, sizeof(he_client_activity_t));
  ca->state = conn.state;

  req->result = -1;
  req->data = ca;

  EXPECT_STATSD_INC("ca_error");
  uv_fs_req_cleanup_ExpectAnyArgs();

  on_client_activity_mkstemp(req);
}

void test_on_client_activity_mkstemp_libuv_error(void) {
  uv_fs_req_cleanup_ExpectAnyArgs();

  uv_fs_write_ExpectAnyArgsAndReturn(-1);
  EXPECT_STATSD_INC("ca_error");
  uv_fs_req_cleanup_ExpectAnyArgs();

  uv_fs_t *req = jecalloc(1, sizeof(uv_fs_t));
  he_client_activity_t *ca = jecalloc(1, sizeof(he_client_activity_t));
  ca->state = conn.state;
  req->result = 42;
  req->data = ca;

  on_client_activity_mkstemp(req);
}

int stub_uv_fs_write(uv_loop_t *loop, uv_fs_t *req, uv_file file, const uv_buf_t bufs[],
                     unsigned int nbufs, int64_t offset, uv_fs_cb cb, int num_calls) {
  // Validate req->data
  TEST_ASSERT_NOT_NULL(req);

  he_client_activity_t *data = (he_client_activity_t *)req->data;

  TEST_ASSERT_NOT_NULL(data);

  TEST_ASSERT_EQUAL(42, file);

  TEST_ASSERT_EQUAL_STRING("test,string", bufs[0].base);

  TEST_ASSERT_EQUAL(1, nbufs);

  TEST_ASSERT_EQUAL(-1, offset);

  // Only call once
  TEST_ASSERT_EQUAL(0, num_calls);

  return 0;
}

int stub_uv_fs_fchmod(uv_loop_t *loop, uv_fs_t *req, uv_file file, int mode, uv_fs_cb cb,
                      int num_calls) {
  TEST_ASSERT_NOT_NULL(req);
  he_client_activity_t *data = (he_client_activity_t *)req->data;
  TEST_ASSERT_NOT_NULL(data);
  TEST_ASSERT_EQUAL(42, file);
  int write_all = (S_IWUSR | S_IWGRP);
  int read_all = (S_IRUSR | S_IRGRP);
  TEST_ASSERT_EQUAL(mode, (write_all | read_all));

  // Only call once
  TEST_ASSERT_EQUAL(0, num_calls);
  return 0;
}

void test_on_client_activity_mkstemp_works(void) {
  uv_fs_write_Stub(stub_uv_fs_write);

  char *test_string = "test,string";
  uv_fs_t *req = jecalloc(1, sizeof(uv_fs_t));
  he_client_activity_t *ca = jecalloc(1, sizeof(he_client_activity_t));
  ca->state = conn.state;
  req->result = 42;
  req->data = ca;
  ca->buffer = stateless_uv_buf_init_for_test(test_string, strlen(test_string), -1);

  uv_fs_req_cleanup_ExpectAnyArgs();

  on_client_activity_mkstemp(req);

  // Otherwise our cleanup function will die here
  ca->buffer.base = 0;
  uv_fs_req_cleanup_ExpectAnyArgs();
  cleanup_pointers(req);
}

void test_on_client_activity_write_bad_result(void) {
  uv_fs_t *req = jecalloc(1, sizeof(uv_fs_t));
  he_client_activity_t *ca = jecalloc(1, sizeof(he_client_activity_t));
  ca->state = conn.state;
  req->result = -1;
  req->data = ca;

  EXPECT_STATSD_INC("ca_error");
  uv_fs_req_cleanup_ExpectAnyArgs();

  on_client_activity_write(req);
}

void test_on_client_activity_chmod(void) {
  uv_fs_close_Stub(stub_uv_fs_close);

  uv_fs_t *req = jecalloc(1, sizeof(uv_fs_t));
  he_client_activity_t *ca = jecalloc(1, sizeof(he_client_activity_t));
  ca->state = conn.state;
  req->result = 100;
  req->data = ca;
  ca->fd = 42;

  on_client_activity_chmod(req);
  uv_fs_req_cleanup_ExpectAnyArgs();
  cleanup_pointers(req);
}

void test_on_client_activity_chmod_general_error(void) {
  uv_fs_close_Stub(stub_uv_fs_close);

  EXPECT_STATSD_INC("ca_error");
  // We explicitly DON'T call cleanup pointers here

  uv_fs_t *req = jecalloc(1, sizeof(uv_fs_t));
  he_client_activity_t *ca = jecalloc(1, sizeof(he_client_activity_t));
  ca->state = conn.state;
  ca->fd = 42;
  req->result = -1;
  req->data = ca;

  on_client_activity_chmod(req);
  uv_fs_req_cleanup_ExpectAnyArgs();
  cleanup_pointers(req);
}

void test_on_client_activity_chmod_libuv_error(void) {
  uv_fs_close_ExpectAnyArgsAndReturn(-1);
  EXPECT_STATSD_INC("ca_error");
  uv_fs_req_cleanup_ExpectAnyArgs();

  uv_fs_t *req = jecalloc(1, sizeof(uv_fs_t));
  he_client_activity_t *ca = jecalloc(1, sizeof(he_client_activity_t));
  ca->state = conn.state;
  req->result = 42;
  req->data = ca;

  on_client_activity_chmod(req);
}

void test_on_client_activity_write_libuv_error(void) {
  uv_fs_fchmod_ExpectAnyArgsAndReturn(-1);
  EXPECT_STATSD_INC("ca_error");
  uv_fs_req_cleanup_ExpectAnyArgs();

  uv_fs_t *req = jecalloc(1, sizeof(uv_fs_t));
  he_client_activity_t *ca = jecalloc(1, sizeof(he_client_activity_t));
  ca->state = conn.state;
  req->result = 42;
  req->data = ca;

  on_client_activity_write(req);
}

void test_on_client_activity_write_works(void) {
  uv_fs_fchmod_Stub(stub_uv_fs_fchmod);

  uv_fs_t *req = jecalloc(1, sizeof(uv_fs_t));
  he_client_activity_t *ca = jecalloc(1, sizeof(he_client_activity_t));
  ca->state = conn.state;
  req->result = 100;
  req->data = ca;
  ca->fd = 42;

  on_client_activity_write(req);
  uv_fs_req_cleanup_ExpectAnyArgs();
  cleanup_pointers(req);
}

void test_on_client_activity_close_bad_result(void) {
  uv_fs_t *req = jecalloc(1, sizeof(uv_fs_t));
  he_client_activity_t *ca = jecalloc(1, sizeof(he_client_activity_t));
  ca->state = conn.state;
  req->result = -1;
  req->data = ca;

  EXPECT_STATSD_INC("ca_error");
  uv_fs_req_cleanup_ExpectAnyArgs();

  on_client_activity_close(req);
}

void test_on_client_activity_close_good_result(void) {
  uv_fs_t *req = jecalloc(1, sizeof(uv_fs_t));
  he_client_activity_t *ca = jecalloc(1, sizeof(he_client_activity_t));
  ca->state = conn.state;
  req->result = 0;
  req->data = ca;
  uv_fs_req_cleanup_ExpectAnyArgs();
  on_client_activity_close(req);
}
