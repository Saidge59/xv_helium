// Test Requirements
#include "unity.h"

// Module Under Test
#include "stub_pkt_maker.h"

void setUp(void) {
}

void tearDown(void) {
}

void test_creating_fake_empty_packet(void) {
  test_packet *empty = fake_empty_packet();
  jefree(empty);
}

void test_creating_fake_string_packet(void) {
  test_packet *dabbad00 = fake_string_packet("dabbad00");
  TEST_ASSERT_EQUAL_STRING("dabbad00", dabbad00->data);
  TEST_ASSERT_EQUAL(9, dabbad00->len);

  jefree(dabbad00);
}
