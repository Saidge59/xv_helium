// Test Requirements
#include "unity.h"
#include "he_test_definitions.h"
#include "lua_setup.h"

// Module Under Test
#include "util.h"

// Third-Party Mocks
#include "mock_zlog.h"

he_server_t state;

void setUp(void) {
  lua_setup(&state);
}

void tearDown(void) {
  lua_teardown(&state);
}

void test_alloc_uv_buffer_tcp() {
  uv_buf_t buf = {0};
  uv_handle_t handle;
  handle.type = UV_TCP;

  alloc_uv_buffer(&handle, HE_SERVER_BUFFER_SIZE, &buf);

  TEST_ASSERT_EQUAL(HE_SERVER_BUFFER_SIZE, buf.len);
  TEST_ASSERT_NOT_EQUAL(NULL, buf.base);
  jefree(buf.base);
}

void test_alloc_uv_buffer_udp() {
  uv_buf_t buf = {0};
  uv_handle_t handle;
  handle.type = UV_UDP;

  alloc_uv_buffer(&handle, HE_SERVER_BUFFER_SIZE, &buf);

  TEST_ASSERT_EQUAL(HE_SERVER_BUFFER_SIZE, buf.len);
  TEST_ASSERT_NOT_EQUAL(NULL, buf.base);
  jefree(buf.base);

   // Test with UV_HANDLE_UDP_RECVMMSG set. There is no official way
   // to do this other than calling `uv_udp_init_ex` which initializes
   // a bunch of other stuff.
  handle.flags |= 0x04000000;

  alloc_uv_buffer(&handle, HE_SERVER_BUFFER_SIZE, &buf);

  TEST_ASSERT_EQUAL(HE_SERVER_BUFFER_SIZE * 20, buf.len);
  TEST_ASSERT_NOT_EQUAL(NULL, buf.base);
  jefree(buf.base);
}

void test_copy_global_lua_int(void) {
  TEST_ASSERT_EQUAL_INT(19655, copy_global_lua_int(&state, "bind_port"));
}

void test_copy_global_lua_int_not_found(void) {
  TEST_ASSERT_EQUAL_INT(15, copy_global_lua_int_default(&state, "renegotiation_timer_min", 15));
}

void test_copy_global_lua_int_default_no_override(void) {
  TEST_ASSERT_EQUAL_INT(19655, copy_global_lua_int_default(&state, "bind_port", 15));
}

void test_copy_global_lua_bool(void) {
  TEST_ASSERT_FALSE(copy_global_lua_bool(&state, "streaming"));
}

void test_copy_global_lua_bool_not_found(void) {
  TEST_ASSERT_TRUE(copy_global_lua_bool_default(&state, "test_boolean", true));
}

void test_copy_global_lua_bool_default_no_override(void) {
  TEST_ASSERT_FALSE(copy_global_lua_bool_default(&state, "streaming", true));
}

void test_access_denied_string(void) {
  TEST_ASSERT_EQUAL_STRING(HE_METRIC_ACCESS_DENIED, "access_denied");
}

void test_copy_global_lua_int64_array(void) {
  int64_t expect[20] = {9094, 6299,  19290, 17569, 21530, 23730, 17147, 13382, 9896,  13550,
                        6203, 14844, 11640, 14206, 6225,  28225, 24082, 19856, 17380, 8860};
  int64_t *arr = NULL;
  size_t len = 0;
  bool res = copy_global_lua_int64_array(&state, "port_scatter_ports", &arr, &len);
  TEST_ASSERT_TRUE(res);
  TEST_ASSERT_EQUAL(20, len);
  TEST_ASSERT_NOT_NULL(arr);
  TEST_ASSERT_EQUAL_MEMORY(expect, arr, sizeof(int64_t) * len);
}

void test_copy_global_lua_string_optional(void) {
  char *actual = copy_global_lua_string_optional(&state, "not_exist");
  TEST_ASSERT_NULL(actual);
}

void test_copy_global_lua_string_default(void) {
  char *actual = copy_global_lua_string_default(&state, "not_exist", "default_string");
  TEST_ASSERT_EQUAL_STRING("default_string", actual);
  jefree(actual);
}

void test_copy_global_lua_string_default_nulls(void) {
  char *actual = copy_global_lua_string_default(&state, "not_exist", NULL);
  TEST_ASSERT_NULL(actual);
}

void test_copy_global_lua_string_default_empty(void) {
  char *actual = copy_global_lua_string_default(&state, "not_exist", "");
  TEST_ASSERT_EQUAL_STRING("", actual);
  jefree(actual);
}

const char src[10] = "123456789";

void test_safe_strncpy(void) {
  TEST_ASSERT_EQUAL(10, sizeof(src));
  TEST_ASSERT_EQUAL(9, strlen(src));

  char dst[10];
  TEST_ASSERT_EQUAL(dst, safe_strncpy(dst, src, sizeof(dst)));
  TEST_ASSERT_EQUAL(dst[10 - 1], '\0');
  TEST_ASSERT_EQUAL_INT(0, strcmp(dst, "123456789"));
}

void test_safe_strncpy_bigger_dst(void) {
  char bigger_dst[15];
  TEST_ASSERT_EQUAL(bigger_dst, safe_strncpy(bigger_dst, src, sizeof(bigger_dst)));
  TEST_ASSERT_EQUAL(bigger_dst[15 - 1], '\0');
  TEST_ASSERT_EQUAL_INT(0, strcmp(bigger_dst, "123456789"));
}

void test_safe_strncpy_smaller_dst(void) {
  char smaller_dst[5];
  TEST_ASSERT_EQUAL(smaller_dst, safe_strncpy(smaller_dst, src, sizeof(smaller_dst)));
  TEST_ASSERT_EQUAL(smaller_dst[5 - 1], '\0');
  TEST_ASSERT_EQUAL_INT(0, strcmp(smaller_dst, "1234"));
}

void test_safe_strncpy_boundary_check(void) {
  char overflow_dst[9];
  TEST_ASSERT_EQUAL(overflow_dst, safe_strncpy(overflow_dst, src, sizeof(overflow_dst)));
  TEST_ASSERT_EQUAL(overflow_dst[9 - 1], '\0');
  TEST_ASSERT_EQUAL_INT(0, strcmp(overflow_dst, "12345678"));
}

