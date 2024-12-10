#ifndef _HE_UTIL_H
#define _HE_UTIL_H
#include <helium.h>

void hexdumpraw(void *ptr, char *result, int buflen);
void hexdump(void *ptr, int buflen);

uint32_t ip2int(const char *ip);
void int2ip(uint32_t ip, char *result, size_t result_size);

/**
 * @brief Safe version of strncpy
 * strncpy has a pitfall that `dst` will not be null terminated if there is no null byte
 * in the first `dst_size` bytes of the array pointed to by `src`
 * This function is a wrapper over strncpy which adds null byte as the last byte
 * @param dst Pointer to the destination char array
 * @param src Pointer to the source char array
 * @param dst_size size of the destination char array
 */
char *safe_strncpy(char *dst, const char *src, size_t dst_size);

void alloc_uv_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

/**
 * @brief Sets up a new Lua state, opens the Lua libraries on that Lua state, and saves the
 * Lua state into the global state.
 * @param state Pointer to the global state
 */
void he_lua_init(he_server_t *state);

/**
 * @brief Loads and runs the given Lua file.
 *
 * @param state Pointer to the global state which contains the lua_State L.
 * @param file Path to the Lua file
 * @return Returns 0 if there's no error. Returns 1 in case of errors.
 */
int he_lua_dofile(he_server_t *state, char const *file);

/**
 * @brief Copies a string from the Lua global state, allocating memory for it. Must be free'd
 * manually
 * @param state Pointer to the global state
 * @param name Global variable name
 * @return A pointer to the Lua string. Program exits if the string doesn't exist in Lua global
 * state.
 */
char const *copy_global_lua_string(he_server_t *state, char const *name);

/**
 * @brief Copies a string from the Lua global state, allocating memory for it. Must be free'd
 * manually
 * @param state Pointer to the global state
 * @param name Global variable name
 * @return A pointer to the Lua string. Returns a copy of the default value if the string doesn't
 * exist in Lua global state.
 */
char const *copy_global_lua_string_default(he_server_t *state, char const *name,
                                           char const *default_val);

/**
 * @brief Copies a string from the Lua global state, allocating memory for it. Must be free'd
 * manually
 * @param state Pointer to the global state
 * @param name Global variable name
 * @return A pointer to the Lua string. Returns NULL if the string doesn't exist in Lua global
 * state.
 */
char const *copy_global_lua_string_optional(he_server_t *state, char const *name);

/**
 * @brief Copies an integer from the LUA global scope
 * @param state Global state
 * @param name LUA global name
 */
int copy_global_lua_int(he_server_t *state, char const *name);
int copy_global_lua_int_default(he_server_t *state, char const *name, int default_val);

/**
 * @brief Copies a double from the LUA global scope
 * @param state Global state
 * @param name LUA global name
 */
double copy_global_lua_double(he_server_t *state, char const *name);

bool copy_global_lua_bool(he_server_t *state, char const *name);
bool copy_global_lua_bool_default(he_server_t *state, char const *name, bool default_val);
bool copy_global_lua_int64_array(he_server_t *state, char const *name, int64_t **out, size_t *len);

/**
 * Return the minimum of two values
 */
static inline uint16_t min_u16(uint16_t a, uint16_t b) {
  return a > b ? b : a;
}

/**
 * Take a sockaddr structure and turn it into an ip and port combo structure for internal
 * representation
 */
he_v4_ip_port_t he_create_ipcombo_v4_from_addr(const struct sockaddr *addr);

/**
 * Returns true if a string only contains alpha-numeric characters
 */
bool he_is_string_valid_alphanum(const char *string_to_test, size_t string_len);

/**
 * Macro to exit the program with error performing any necessary tear down. In a test, the test
 * *will* fail on an unexpected call to test_exit -- TEST_PASS() seems odd but it forces the test to
 * exit successfully and  really does allow us to test that we call failure without actually
 * crashing the test.
 */
#ifdef TEST
#include "fake_exit.h"
#define HE_EXIT_WITH_FAILURE() \
  test_exit(EXIT_FAILURE);     \
  TEST_PASS();
#else
#define HE_EXIT_WITH_FAILURE() exit(EXIT_FAILURE)
#endif

/**
 * Exit the program if this expression isn't true (should be used where condition violation is a
 * serious / impossible error) Similar to assert but runs outside of debug mode
 */
#ifdef TEST
#include "unity.h"
#define HE_CHECK_WITH_MSG(expression, msg)                                     \
  if(!(expression)) {                                                          \
    TEST_FAIL_MESSAGE("Fatal assertion " #expression " caused check failure"); \
  }
#else
#define HE_CHECK_WITH_MSG(expression, msg)                                                        \
  if(!(expression)) {                                                                             \
    zlogf_time(ZLOG_INFO_LOG_MSG,                                                                 \
               "Fatal assertion " #expression " violated (%s) in %s at %s:%i\n", (msg), __FILE__, \
               __func__, __LINE__);                                                               \
    zlog_finish();                                                                                \
    HE_EXIT_WITH_FAILURE();                                                                       \
  }
#endif

/**
 * Check if the expr is not equal to HE_SUCCESS and if so, log msg and goto a cleanup label.
 *
 */
#define HE_SUCCESS_OR_CLEANUP(expression, msg)                                          \
  do {                                                                                  \
    he_return_code_t ret = (expression);                                                \
    if(ret != HE_SUCCESS) {                                                             \
      zlogf_time(ZLOG_INFO_LOG_MSG,                                                     \
                 "libhelium error:" #expression ": %i (%s) : %s in %s at %s:%i\n", ret, \
                 he_return_code_name(ret), (msg), __FILE__, __func__, __LINE__);        \
      zlog_flush_buffer();                                                              \
      goto cleanup;                                                                     \
    }                                                                                   \
  } while(0)

/**
 * Check if the expr is not equal to HE_SUCCESS and if so, log msg and return that code
 *
 */
#define HE_SUCCESS_OR_RETURN(expression, msg)                                           \
  do {                                                                                  \
    he_return_code_t ret = (expression);                                                \
    if(ret != HE_SUCCESS) {                                                             \
      zlogf_time(ZLOG_INFO_LOG_MSG,                                                     \
                 "libhelium error:" #expression ": %i (%s) : %s in %s at %s:%i\n", ret, \
                 he_return_code_name(ret), (msg), __FILE__, __func__, __LINE__);        \
      zlog_flush_buffer();                                                              \
      return ret;                                                                       \
    }                                                                                   \
  } while(0)

/**
 * Out of the box, Unity doesn't allow us to mock intra-module function calls.
 * This is generally OK but is *very* annoying for the packet lifecycle functions,
 * where we pass control to a bunch of various functions in a pipeline, so
 * instead of artifically breaking these functions into different modules we
 * just mock the "handover" here with a dispatch macro.
 *
 * If TEST isn't defined this just compiles down to a function call, so there's
 * zero performance penalty AND we would get compile errors if the function is
 * called incorrectly.
 */
#ifdef TEST
#include "fake_dispatch.h"  // Never implemented, only used as a mock
#define HE_FLOW_DISPATCH(func, ...) dispatch("" #func "", ##__VA_ARGS__)
#else
#define HE_FLOW_DISPATCH(func, ...) func(__VA_ARGS__)
#endif
#ifdef TEST
#include "fake_dispatch.h"  // Never implemented, only used as a mock
#define HE_FLOW_DISPATCH_BOOL(func, ...) dispatch_bool("" #func "", ##__VA_ARGS__)
#else
#define HE_FLOW_DISPATCH_BOOL(func, ...) func(__VA_ARGS__)
#endif

/**
 * uv_hrtime() returns values in nanoseconds, but we often want to convert to milliseconds
 */
#define HE_NS_TO_MS(ns_value) ((ns_value) / 1000000)

/**
 * Convenience constants for metrics used throughout the codebase.
 * This is not intended to imply that ALL metrics must be defined here.
 */
#define HE_METRIC_MAX_LENGTH 64
#define HE_METRIC_ACCESS_DENIED "access_denied"
#define HE_METRIC_SSL_ERROR "ssl_error"
#define HE_METRIC_SSL_ERROR_NONFATAL "non_fatal_ssl_error"
#define HE_METRIC_CONN_CLOSED "conn_closed"
#define HE_METRIC_SESSION_ROTATION_BEGIN "session_id_rotation_initiated"
#define HE_METRIC_SESSION_ROTATION_FINALIZE "session_id_rotation_accepted"
#define HE_METRIC_USER_AGED_OUT "user_age_eviction"
#define HE_METRIC_USER_EVICTED "user_auth_eviction"
#define HE_METRIC_USER_EVICTED_NO_RENEGOTIATION "user_no_renegotiation_eviction"
#define HE_METRIC_RENEGOTIATION_STARTED "renegotiation_started"
#define HE_METRIC_RENEGOTIATION_COMPLETED "renegotiation_completed"
#define HE_METRIC_REJECTED_TUN_PACKETS "rejected_tun_packets"
#define HE_METRIC_UNKNOWN_FATAL_ERROR "unknown_fatal_error"
#define HE_METRIC_UNKNOWN_NONFATAL_ERROR "unknown_non_fatal_error"
#define HE_METRIC_SECURE_RENEGOTIATION_ERROR "secure_renegotiation_error"
#define HE_METRIC_ASSIGN_INSIDE_IP_ERROR "assign_inside_ip_error"

#define HE_METRIC_LINK_UP_AES "link_up_with_aes"
#define HE_METRIC_LINK_UP_CHACHA20 "link_up_with_chacha20"

#define HE_METRIC_LINK_UP_TLS_1_3 "link_up_with_tls_1_3"
#define HE_METRIC_LINK_UP_DTLS_1_2 "link_up_with_dtls_1_2"
#define HE_METRIC_LINK_UP_DTLS_1_3 "link_up_with_dtls_1_3"

#define HE_METRIC_LINK_UP_ECC "link_up_with_ecc"
#define HE_METRIC_LINK_UP_PQC "link_up_with_pqc"
#define HE_METRIC_LINK_UP_PQC_ML_KEM "link_up_with_pqc_ml_kem"
#define HE_METRIC_LINK_UP_UNKNOWN_KEM "link_up_with_unknown_kem"

#define HE_METRIC_AUTH_SUCCESS_USER_PASS "auth_success_with_user_pass"
#define HE_METRIC_AUTH_SUCCESS_AUTH_BUF "auth_success_with_auth_buf"
#define HE_METRIC_AUTH_SUCCESS_AUTH_TOKEN "auth_success_with_auth_token"

#define HE_METRIC_ONLINE_WITH_PROTOCOL_V1_0 "online_with_protocol_v1_0"
#define HE_METRIC_ONLINE_WITH_PROTOCOL_V1_1 "online_with_protocol_v1_1"
#define HE_METRIC_ONLINE_WITH_PROTOCOL_V1_2 "online_with_protocol_v1_2"
#define HE_METRIC_ONLINE_WITH_PROTOCOL_UNKNOWN "online_with_protocol_unknown"

#define HE_METRIC_INCOMING "incoming"
#define HE_METRIC_OUTGOING "outgoing"
#define HE_METRIC_RECOVERED_SESSION "recovered_session"
#define HE_METRIC_REJECTED_SESSION "rejected_session"
#define HE_METRIC_OLD_PROTOCOL_SESSION "old_protocol_session"
#define HE_METRIC_BAD_PACKET_VERSION "bad_packet_version"
#define HE_METRIC_PLUGIN_ERROR "plugin_error"
#define HE_METRIC_PLUGIN_LENGTH_ERROR "plugin_length_error"

#define HE_METRIC_INCOMING_TIME "incoming_time"
#define HE_METRIC_OUTGOING_TIME "outgoing_time"
#define HE_METRIC_TO_LINK_UP_TIME "to_link_up_time"
#define HE_METRIC_TO_ONLINE_TIME "to_online_time"

#define HE_METRIC_INVALID_HPT_PACKET_ZERO_SIZE "invalid_hpt_packet_zero_size"
#define HE_METRIC_INVALID_HPT_PACKET_OVER_SIZED "invalid_hpt_packet_over_sized"
#define HE_METRIC_INVALID_HPT_PACKET_SPOOFED_INSIDE_IP "invalid_hpt_packet_spoofed_inside_ip"

#define HE_METRIC_INVALID_TUN_PACKET_SPOOFED_INSIDE_IP "invalid_tun_packet_spoofed_inside_ip"

#endif
