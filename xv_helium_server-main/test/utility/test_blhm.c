/** Taken from https://github.com/jawline/blakec **/
#include "unity.h"
#include "blhm.h"
#include <stdio.h>

int cmp_key(int m, int r) {
  return m - r;
}

size_t int_map_hash(int m) {
  return m;
}

HASH_MAP(int_map, int, int, int_map_hash, cmp_key, 16, 1024);

struct int_map a;

void setUp(void) {
  int_map_init(&a);
}

void tearDown(void) {
  int_map_free(&a);
}

void test_num_buckets() {
  TEST_ASSERT_EQUAL(int_map_num_buckets(&a), 16);
}

void test_set_and_find() {
  int_map_set(&a, 5, 50);

  // Find pointer and find achieve the same thing with different behaviours.
  // Test both here
  TEST_ASSERT_EQUAL(*int_map_find_ptr(&a, 5), 50);

  int found_value;
  TEST_ASSERT_EQUAL(int_map_find(&a, 5, &found_value), true);
  TEST_ASSERT_EQUAL(found_value, 50);

  TEST_ASSERT_EQUAL(int_map_count(&a), 1);
}

void test_set_and_replacement_and_find() {
  int_map_set(&a, 5, 50);
  int_map_set(&a, 5, 20);

  // Find pointer and find achieve the same thing with different behaviours.
  // Test both here
  TEST_ASSERT_EQUAL(*int_map_find_ptr(&a, 5), 20);

  int found_value;
  TEST_ASSERT_EQUAL(int_map_find(&a, 5, &found_value), true);
  TEST_ASSERT_EQUAL(found_value, 20);

  TEST_ASSERT_EQUAL(int_map_count(&a), 1);
}

void test_find_missing_element() {
  // Find pointer and find achieve the same thing with different behaviours.
  // Test both here
  TEST_ASSERT_EQUAL(int_map_find_ptr(&a, 5), NULL);

  int found_value;
  TEST_ASSERT_EQUAL(int_map_find(&a, 5, &found_value), false);

  TEST_ASSERT_EQUAL(int_map_count(&a), 0);
}

void test_set_and_remove() {
  int_map_set(&a, 5, 50);
  int_map_remove(&a, 5);
  TEST_ASSERT_EQUAL(int_map_find_ptr(&a, 5), NULL);
  TEST_ASSERT_EQUAL(int_map_count(&a), 0);
}

void test_remove_nothing() {
  int_map_remove(&a, 5);
  TEST_ASSERT_EQUAL(int_map_count(&a), 0);
}

void test_set_and_remove_nothing() {
  int_map_set(&a, 5, 50);
  int_map_remove(&a, 10);
  TEST_ASSERT_EQUAL(*int_map_find_ptr(&a, 5), 50);
  TEST_ASSERT_EQUAL(int_map_count(&a), 1);
}

void test_add_two_remove_one() {
  int_map_set(&a, 5, 50);
  int_map_set(&a, 6, 50);
  int_map_remove(&a, 5);
  TEST_ASSERT_EQUAL(int_map_find_ptr(&a, 5), NULL);
  TEST_ASSERT_EQUAL(*int_map_find_ptr(&a, 6), 50);
  TEST_ASSERT_EQUAL(int_map_count(&a), 1);
}

/// This test makes sure that data doesn't get corrupted even in loaded buckets
void test_remove_from_loaded_buckets() {
  // Load up a map
  for(size_t i = 0; i < 10000; i++) {
    int_map_set(&a, i, i + 10);
  }

  // Delete the middle element
  int_map_remove(&a, 5000);

  // Check for consistency
  for(size_t i = 0; i < 10000; i++) {
    int *found_ptr = int_map_find_ptr(&a, i);
    if(i == 5000) {
      TEST_ASSERT_EQUAL(found_ptr, NULL);
    } else {
      TEST_ASSERT_EQUAL(*found_ptr, i + 10);
    }
  }

  TEST_ASSERT_EQUAL(int_map_count(&a), 9999);
}

void test_change_key() {
  int_map_set(&a, 5, 50);
  int_map_change_key(&a, 5, 10);
  TEST_ASSERT_EQUAL(*int_map_find_ptr(&a, 10), 50);
  TEST_ASSERT_EQUAL(int_map_count(&a), 1);
}

void test_change_missing_key() {
  int_map_change_key(&a, 5, 10);
  TEST_ASSERT_EQUAL(int_map_count(&a), 0);
}

void test_change_one_in_two() {
  int_map_set(&a, 5, 50);
  int_map_set(&a, 10, 100);
  int_map_change_key(&a, 5, 15);
  TEST_ASSERT_EQUAL(*int_map_find_ptr(&a, 15), 50);
  TEST_ASSERT_EQUAL(int_map_count(&a), 2);
}

void test_change_replace() {
  int_map_set(&a, 5, 50);
  int_map_set(&a, 10, 100);
  int_map_change_key(&a, 5, 10);
  TEST_ASSERT_EQUAL(*int_map_find_ptr(&a, 10), 50);
  TEST_ASSERT_EQUAL(int_map_count(&a), 1);
}

/// This test makes sure that data doesn't get corrupted even in loaded buckets
void test_change_inloaded_buckets() {
  // Load up a map
  for(size_t i = 0; i < 10000; i++) {
    int_map_set(&a, i, i + 10);
  }

  // Delete the middle element
  int_map_change_key(&a, 5000, 0);

  // Check for consistency
  for(size_t i = 0; i < 10000; i++) {
    int *found_ptr = int_map_find_ptr(&a, i);
    if(i == 0) {
      TEST_ASSERT_EQUAL(*found_ptr, 5010);
    } else if(i == 5000) {
      TEST_ASSERT_EQUAL(found_ptr, NULL);
    } else {
      TEST_ASSERT_EQUAL(*found_ptr, i + 10);
    }
  }

  TEST_ASSERT_EQUAL(int_map_count(&a), 9999);
}

/// Sanity test that we haven't bungled up globals and can have coexisting maps
void test_init_many() {
  struct int_map b, c, d;
  int_map_init(&b);
  int_map_init(&c);
  int_map_init(&d);

  for(size_t i = 0; i < 100; i++) {
    int_map_set(&b, i, i);
  }

  for(size_t i = 0; i < 1000; i++) {
    int_map_set(&c, i, i + 1);
  }

  for(size_t i = 0; i < 10000; i++) {
    int_map_set(&d, i, i + 2);
  }

  for(size_t i = 0; i < 100; i++) {
    TEST_ASSERT_EQUAL((*int_map_find_ptr(&b, i)) + 1, (*int_map_find_ptr(&c, i)));
  }

  for(size_t i = 0; i < 1000; i++) {
    TEST_ASSERT_EQUAL((*int_map_find_ptr(&c, i)) + 1, (*int_map_find_ptr(&d, i)));
  }

  for(size_t i = 0; i < 10000; i++) {
    TEST_ASSERT_EQUAL(*int_map_find_ptr(&d, i), i + 2);
  }

  TEST_ASSERT_EQUAL(int_map_count(&b), 100);
  TEST_ASSERT_EQUAL(int_map_count(&c), 1000);
  TEST_ASSERT_EQUAL(int_map_count(&d), 10000);

  int_map_free(&b);
  int_map_free(&c);
  int_map_free(&d);
}

void test_general_usage() {
  int_map_set(&a, 5, 10);
  int_map_set(&a, 10, 10);
  int_map_set(&a, 5, 50);
  int_map_set(&a, 10, 5);

  TEST_ASSERT_EQUAL(*int_map_find_ptr(&a, 5), 50);
  TEST_ASSERT_EQUAL(*int_map_find_ptr(&a, 10), 5);
  TEST_ASSERT_EQUAL(int_map_find_ptr(&a, 13210), NULL);
  TEST_ASSERT_EQUAL(int_map_find_ptr(&a, 132111), NULL);

  int value;

  TEST_ASSERT_EQUAL(int_map_find(&a, 5, &value), true);
  TEST_ASSERT_EQUAL(value, 50);
  TEST_ASSERT_EQUAL(int_map_find(&a, 10, &value), true);
  TEST_ASSERT_EQUAL(value, 5);
  TEST_ASSERT_EQUAL(int_map_find(&a, 24123123, &value), false);
  TEST_ASSERT_EQUAL(int_map_find(&a, 231312, &value), false);

  int_map_remove(&a, 5);
  TEST_ASSERT_EQUAL(int_map_find_ptr(&a, 5), NULL);
  TEST_ASSERT_EQUAL(*int_map_find_ptr(&a, 10), 5);

  printf("Remove 5\n");

  int_map_remove(&a, 5);
  TEST_ASSERT_EQUAL(int_map_find_ptr(&a, 5), NULL);
  TEST_ASSERT_EQUAL(*int_map_find_ptr(&a, 10), 5);

  printf("Remove 10\n");

  int_map_remove(&a, 10);
  TEST_ASSERT_EQUAL(int_map_find_ptr(&a, 10), NULL);
  TEST_ASSERT_EQUAL(int_map_find_ptr(&a, 10), NULL);
}

int touched = 0;
int deleted = 0;

bool delete_callback(struct int_map_entry *v) {
  touched += 1;
  return v->key % 2;
}

void post_delete_callback(struct int_map_entry *v) {
  deleted += 1;
}

void test_delete_matching() {
  // Load up a map
  for(size_t i = 0; i < 10000; i++) {
    int_map_set(&a, i, i);
  }

  int_map_delete_matching(&a, delete_callback, post_delete_callback);

  // Test that we deleted every even key and that the map is smaller because of it
  TEST_ASSERT_EQUAL(touched, 10000);
  TEST_ASSERT_EQUAL(deleted, 5000);
  TEST_ASSERT_EQUAL(int_map_count(&a), 5000);
}
