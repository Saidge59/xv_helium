/** Taken from https://github.com/jawline/blakec **/
#include "unity.h"

size_t illegal_ops = 0;

#define LIST_ILLEGAL_OP(msg) \
  illegal_ops += 1;          \
  return 0;
#define LIST_ILLEGAL_CONCAT(msg) \
  illegal_ops += 1;              \
  return;
#include "bllist.h"
DYNAMIC_ARRAY(int_list, int, 32);

struct int_list l1;
struct int_list l2;

void setUp() {
  int_list_init(&l1);
  int_list_init(&l2);
  illegal_ops = 0;
}

void tearDown() {
  int_list_free(&l1);
  int_list_free(&l2);
}

void test_push() {
  int_list_push(&l1, 5042);
  TEST_ASSERT_EQUAL(l1.data[0], 5042);
  TEST_ASSERT_EQUAL(int_list_size(&l1), 1);
}

void test_push_pop_push() {
  int_list_push(&l1, 5042);
  TEST_ASSERT_EQUAL(int_list_pop(&l1), 5042);
  int_list_push(&l1, 1096);
  TEST_ASSERT_EQUAL(l1.data[0], 1096);
  TEST_ASSERT_EQUAL(int_list_size(&l1), 1);
  TEST_ASSERT_EQUAL(int_list_pop(&l1), 1096);
}

void test_push_pop_pop_triggers_illegal_op() {
  int_list_push(&l1, 5042);
  TEST_ASSERT_EQUAL(int_list_pop(&l1), 5042);
  TEST_ASSERT_EQUAL(int_list_size(&l1), 0);
  TEST_ASSERT_EQUAL(illegal_ops, 0);
  int_list_pop(&l1);
  TEST_ASSERT_EQUAL(illegal_ops, 1);
}

void test_pop() {
  int_list_push(&l1, 5042);
  TEST_ASSERT_EQUAL(int_list_pop(&l1), 5042);
  TEST_ASSERT_EQUAL(int_list_size(&l1), 0);
}

void test_pop_empty_triggers_illegal_op_exit() {
  int_list_pop(&l1);
  TEST_ASSERT_EQUAL(illegal_ops, 1);
}

void test_pop_ordering() {
  int_list_push(&l1, 1);
  int_list_push(&l1, 2);
  int_list_push(&l1, 3);
  int_list_push(&l1, 4);
  int_list_push(&l1, 5);
  for(size_t i = 0; i < 5; i++) {
    TEST_ASSERT_EQUAL(l1.data[i], i + 1);
  }
  TEST_ASSERT_EQUAL(int_list_pop(&l1), 5);
  TEST_ASSERT_EQUAL(int_list_pop(&l1), 4);
  TEST_ASSERT_EQUAL(int_list_pop(&l1), 3);
  TEST_ASSERT_EQUAL(int_list_pop(&l1), 2);
  TEST_ASSERT_EQUAL(int_list_pop(&l1), 1);
  TEST_ASSERT_EQUAL(int_list_size(&l1), 0);
}

void test_remove_single() {
  int_list_push(&l1, 50);
  int k = int_list_remove(&l1, 0);
  TEST_ASSERT_EQUAL(int_list_size(&l1), 0);
}

void test_remove_from_big_list() {
  for(size_t i = 0; i < 10000; i++) {
    int_list_push(&l1, i - 3);
  }

  TEST_ASSERT_EQUAL(int_list_remove(&l1, 0), -3);
  TEST_ASSERT_EQUAL(int_list_remove(&l1, 0), -2);
  TEST_ASSERT_EQUAL(int_list_remove(&l1, 0), -1);

  for(size_t i = 0; i < 10000 - 3; i++) {
    TEST_ASSERT_EQUAL(l1.data[i], i);
  }
}

void test_remove_invalid_index_triggers_illegal_op_exit() {
  // Remove a nonexistant element
  int_list_remove(&l1, 0);
  TEST_ASSERT_EQUAL(illegal_ops, 1);

  // Add a new element (legal)
  int_list_push(&l1, 50);
  TEST_ASSERT_EQUAL(illegal_ops, 1);

  // Remove a non-existant element (illegal)
  int_list_remove(&l1, 232131);
  TEST_ASSERT_EQUAL(illegal_ops, 2);

  // Remove the element we just added (legal)
  int_list_remove(&l1, 0);
  TEST_ASSERT_EQUAL(illegal_ops, 2);

  // Double remove (illegal, since the list doesn't have that index now)
  int_list_remove(&l1, 0);
  TEST_ASSERT_EQUAL(illegal_ops, 3);
}

void test_push_many() {
  for(size_t i = 0; i < 10000; i++) {
    int_list_push(&l1, i * 100);
  }

  for(size_t i = 0; i < int_list_size(&l1); i++) {
    TEST_ASSERT_EQUAL(l1.data[i], i * 100);
  }

  TEST_ASSERT_EQUAL(int_list_size(&l1), 10000);
}

void test_pop_many() {
  for(size_t i = 0; i < 10000; i++) {
    int_list_push(&l1, i * 100);
  }

  size_t last = int_list_size(&l1);

  for(size_t i = 0; i < 10000; i++) {
    TEST_ASSERT_EQUAL(int_list_pop(&l1), ((10000 - 1) - i) * 100);
    TEST_ASSERT_EQUAL(int_list_size(&l1), last - 1);
    last = int_list_size(&l1);
  }

  TEST_ASSERT_EQUAL(int_list_size(&l1), 0);

  int_list_push(&l1, 5);
  int_list_push(&l1, 10);

  TEST_ASSERT_EQUAL(int_list_remove(&l1, 0), 5);
  TEST_ASSERT_EQUAL(int_list_size(&l1), 1);

  TEST_ASSERT_EQUAL(int_list_remove(&l1, 0), 10);
  TEST_ASSERT_EQUAL(int_list_size(&l1), 0);
}

void test_concat() {
  printf("Filling arrays\n");
  for(size_t i = 0; i < 10000; i++) {
    int_list_push(&l1, i * 100);
    int_list_push(&l2, i);
  }

  printf("Concatenating arrays\n");
  int_list_concat(&l1, &l2);

  printf("Checking Size\n");
  TEST_ASSERT_EQUAL(int_list_size(&l1), 20000);
  TEST_ASSERT_EQUAL(int_list_size(&l2), 10000);

  printf("Checking data\n");
  for(size_t i = 0; i < 10000; i++) {
    TEST_ASSERT_EQUAL(l1.data[i], i * 100);
    TEST_ASSERT_EQUAL(l1.data[i + 10000], i);
  }

  for(size_t i = 0; i < 100000; i++) {
    int_list_push(&l1, i * 100);
  }

  for(size_t i = 0; i < 100000; i++) {
    TEST_ASSERT_EQUAL(l1.data[i + 20000], i * 100);
  }
}

void test_concat_safety_check() {
  int_list_concat(&l1, &l2);
  TEST_ASSERT_EQUAL(illegal_ops, 0);

  int_list_concat(&l1, NULL);
  TEST_ASSERT_EQUAL(illegal_ops, 1);

  int_list_concat(&l2, NULL);
  TEST_ASSERT_EQUAL(illegal_ops, 2);

  int_list_concat(NULL, &l1);
  TEST_ASSERT_EQUAL(illegal_ops, 3);

  int_list_concat(NULL, &l2);
  TEST_ASSERT_EQUAL(illegal_ops, 4);

  struct int_list ltemp = {0};

  int_list_concat(&l1, &ltemp);
  TEST_ASSERT_EQUAL(illegal_ops, 5);
}

void test_grows() {
  TEST_ASSERT_EQUAL(l1.capacity, 32);
  size_t cap = l1.capacity;
  for(size_t i = 0; i < cap + 1; i++) {
    int_list_push(&l1, 0);
  }
  TEST_ASSERT_EQUAL(l1.capacity, 64);
}

void test_shrink() {
  TEST_ASSERT_EQUAL(l1.capacity, 32);

  size_t initial_shrink = l1.shrink_at;
  size_t cap = l1.capacity;

  TEST_ASSERT_EQUAL(initial_shrink, 0);

  for(size_t i = 0; i < cap + 1; i++) {
    int_list_push(&l1, 0);
  }

  size_t first_shrink = l1.shrink_at;
  TEST_ASSERT_LESS_THAN(l1.current, l1.shrink_at);

  size_t cap2 = l1.capacity;

  for(size_t i = cap; i < cap2 + 1; i++) {
    int_list_push(&l1, 0);
  }

  TEST_ASSERT_LESS_THAN(l1.current, l1.shrink_at);
  TEST_ASSERT_LESS_THAN(l1.shrink_at, first_shrink);

  size_t shrink_two = l1.shrink_at;
  size_t amount_to_shrink = l1.current - l1.shrink_at;

  for(size_t i = 0; i < amount_to_shrink; i++) {
    int_list_pop(&l1);
  }

  // Should have now shrunk to half the size
  TEST_ASSERT_EQUAL(l1.shrink_at, first_shrink);
  TEST_ASSERT_EQUAL(cap2, l1.capacity);

  amount_to_shrink = l1.current - l1.shrink_at;

  for(size_t i = 0; i < amount_to_shrink; i++) {
    int_list_pop(&l1);
  }

  // Now that capacity = SIZE make sure that
  // the capacity does not change again

  TEST_ASSERT_EQUAL(l1.shrink_at, 0);
  TEST_ASSERT_EQUAL(l1.capacity, 32);

  while(int_list_size(&l1)) {
    int_list_pop(&l1);
  }

  TEST_ASSERT_EQUAL(l1.shrink_at, 0);
  TEST_ASSERT_EQUAL(l1.capacity, 32);
}
