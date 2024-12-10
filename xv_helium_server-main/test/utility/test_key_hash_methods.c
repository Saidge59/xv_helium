// Test Requirements
#include "unity.h"

#include <arpa/inet.h>

// Module Under Test
#include "key_hash_methods.h"

void setUp(void) {
}

void tearDown(void) {
}

void test_compare_v4_ip_port_equal(void) {
    he_v4_ip_port_t left = {
        .ip = 420,
        .port = 69,
    };

    he_v4_ip_port_t right = {
        .ip = 420,
        .port = 69,
    };
    TEST_ASSERT_EQUAL(0, compare_v4_ip_port(left , right));
}

void test_compare_v4_ip_port_equal_ip_different_port(void) {
    he_v4_ip_port_t left = {
        .ip = 420,
        .port = 42,
    };

    he_v4_ip_port_t right = {
        .ip = 420,
        .port = 69,
    };
    TEST_ASSERT_EQUAL(-1, compare_v4_ip_port(left , right));
    TEST_ASSERT_EQUAL(1, compare_v4_ip_port(right , left));
}

void test_compare_v4_ip_port_different_ip(void) {
    he_v4_ip_port_t left = {
        .ip = 69,
        .port = 69,
    };

    he_v4_ip_port_t right = {
        .ip = 420,
        .port = 69,
    };
    TEST_ASSERT_EQUAL(-1, compare_v4_ip_port(left , right));
    TEST_ASSERT_EQUAL(1, compare_v4_ip_port(right , left));
}

void test_v4_ip_port_hash(void) {
    he_v4_ip_port_t ip_port = {
        .ip = 420,
        .port = 69,
    };
    TEST_ASSERT_EQUAL(27525189, v4_ip_port_hash(ip_port));
}

void test_compare_ipv4_equal(void) {
    uint32_t left = 420;
    uint32_t right = 420;

    TEST_ASSERT_EQUAL(0, compare_ipv4(left , right));
}

void test_compare_ipv4_different(void) {
    uint32_t left = 69;
    uint32_t right = 420;

    TEST_ASSERT_EQUAL(-1, compare_ipv4(left , right));
    TEST_ASSERT_EQUAL(1, compare_ipv4(right , left));
}

void test_ipv4_hash(void) {
    uint32_t ip = htonl(69);

    TEST_ASSERT_EQUAL(69, ipv4_hash(ip));
}

void test_compare_session_id_equal(void) {
    uint64_t left = 420;
    uint64_t right = 420;

    TEST_ASSERT_EQUAL(0, compare_session_id(left , right));
}

void test_compare_session_id_different(void) {
    uint64_t left = 69;
    uint64_t right = 420;

    TEST_ASSERT_EQUAL(-1, compare_session_id(left , right));
    TEST_ASSERT_EQUAL(1, compare_session_id(right , left));
}

void test_session_id_hash(void) {
    uint64_t session_id = 69420;

    TEST_ASSERT_EQUAL(69420, session_id_hash(session_id));
}
