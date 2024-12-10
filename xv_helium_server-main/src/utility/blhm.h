/** Taken from https://github.com/jawline/blakec **/
#ifndef _BLAKE_HM_H_
#define _BLAKE_HM_H_
#include "bllist.h"
#include <stdbool.h>

/**
 * This hash map implementation is backed by dynamically allocated arrays, and uses a
 * fixed number of buckets. This is driven by the observation in many of our use cases
 * that when map sizes are relatively small (<60k elements) using a more complex implementation
 * does not improve performance but does make debugging more difficult.
 *
 * The performance profile of this hashmap is straightforward, a hash function is used to select
 * a 'bucket' from a fixed number of available buckets, and then does a linear scan through that
 * bucket to find elements, or appends to the end of that list with new elements.
 *
 * POTENTIAL TODO: It would not be a stretch to include a version of insert that sorts lists and
 * enables binary search. We may add this later.
 *
 * This implementation uses macros to construct a typed hash-map implementation for a
 * given key-value pair. It uses a user-supplied hashing function, key type and value type to create
 * a map structure, entry structure, and a structure for the dynamic array which backs buckets
 * (using the dynamic array implementation in bllist.h).
 *
 * Since the macro definition of this hash map knows the storage type we avoid the common trope
 * of using void* to store entries. This has two key advantages, this map can store structures
 * directly, without requiring memory allocation for them, and the generated hash methods are
 * type safe, in that since you do not cast on insert and get the compiler will complain if you
 * insert an element of the wrong type to a list.
 *
 */
#define HASH_MAP_TYPE(NAME, KEY_TYPE, DATA_TYPE, BUCKETS, BLOCK_SIZE) \
  typedef struct NAME##_entry {                                       \
    KEY_TYPE key;                                                     \
    DATA_TYPE data;                                                   \
  } NAME##_entry_t;                                                   \
  DYNAMIC_ARRAY(NAME##_bucket, struct NAME##_entry, BLOCK_SIZE);      \
  typedef struct NAME {                                               \
    struct NAME##_bucket buckets[BUCKETS];                            \
  } NAME##_t;

/**
 * _init puts a map structure into a state where it is ready to include elements.
 * This function must be called before the hashmap is used.
 */
#define HASH_MAP_INIT(NAME, BUCKETS)                 \
  static inline void NAME##_init(struct NAME *map) { \
    for(size_t i = 0; i < BUCKETS; i++) {            \
      NAME##_bucket_init(&map->buckets[i]);          \
    }                                                \
  }

/**
 * _free free's any memory associated with the hash map.
 * NOTE: This does not free underlying memory in cases
 * where DATA_TYPE is a pointer. That is left to the user
 */
#define HASH_MAP_FREE(NAME, BUCKETS)                 \
  static inline void NAME##_free(struct NAME *map) { \
    for(size_t i = 0; i < BUCKETS; i++) {            \
      NAME##_bucket_free(&map->buckets[i]);          \
    }                                                \
  }

/**
 * The method this macro generates returns the bucket that a given key-value
 * pair will be placed into when inserted into the hash map.
 */
#define HASH_MAP_GET_BUCKET(NAME, KEY_TYPE, BUCKETS, HASH_FN) \
  static inline size_t NAME##_get_bucket(KEY_TYPE key) {      \
    return HASH_FN(key) % BUCKETS;                            \
  }

/**
 * _find_ptr returns a pointer to any matching element inside the map or NULL otherwise.
 * If find_ptr finds an element, then updating the element by dereferencing will change
 * the underlying value in the map. For example NAME_insert(5, "Bye"); *NAME_find(5) = "Hello";
 * will update the element at key 5 from "Bye" to "Hello".
 *
 * WARNING: find_ptr is not stable between inserts, updates, or deletions since value locations
 * may change in the buckets or buckets may be re-allocated.
 */
#define HASH_MAP_FIND_PTR(NAME, KEY_TYPE, DATA_TYPE, CMP_FN)                 \
  static inline DATA_TYPE *NAME##_find_ptr(struct NAME *map, KEY_TYPE key) { \
    size_t bucket_idx = NAME##_get_bucket(key);                              \
    struct NAME##_bucket *bucket = &map->buckets[bucket_idx];                \
    size_t bucket_size = NAME##_bucket_size(bucket);                         \
    for(size_t i = 0; i < bucket_size; i++) {                                \
      if(!CMP_FN(key, bucket->data[i].key)) {                                \
        return &bucket->data[i].data;                                        \
      }                                                                      \
    }                                                                        \
    return NULL;                                                             \
  }

/**
 * _find returns true or false if an element with a given key exists inside the map.
 * The data argument will be ignored if set to NULL or the element does not exist
 * within the map,otherwise the pointed value will be set to the in the value with
 * the corresponding key (*data = *NAME_find_ptr(map, key)).
 */
#define HASH_MAP_FIND(NAME, KEY_TYPE, DATA_TYPE, CMP_FN)                            \
  static inline bool NAME##_find(struct NAME *map, KEY_TYPE key, DATA_TYPE *data) { \
    DATA_TYPE *ptr = NAME##_find_ptr(map, key);                                     \
    if(ptr) {                                                                       \
      if(data) {                                                                    \
        *data = *ptr;                                                               \
      }                                                                             \
      return true;                                                                  \
    } else {                                                                        \
      return false;                                                                 \
    }                                                                               \
  }

/**
 * _remove function scans the bucket that the key will be
 * in for an element with that key and removes the key-value pair
 * from the bucket array.
 */
#define HASH_MAP_REMOVE(NAME, KEY_TYPE, CMP_FN)                      \
  static inline void NAME##_remove(struct NAME *map, KEY_TYPE key) { \
    size_t bucket_idx = NAME##_get_bucket(key);                      \
    struct NAME##_bucket *bucket = &map->buckets[bucket_idx];        \
    size_t bucket_size = NAME##_bucket_size(bucket);                 \
    for(size_t i = 0; i < bucket_size; i++) {                        \
      if(!CMP_FN(key, bucket->data[i].key)) {                        \
        NAME##_bucket_remove(bucket, i);                             \
        return;                                                      \
      }                                                              \
    }                                                                \
  }

/**
 * _set places the supplied key-value pair into the hash map.
 * First, _set does a find_ptr for existing keys.
 *
 * If this key is in the hasmap then _set replaces the value associated with
 * that key with the supplied value.
 *
 * If the key does not already exist in the hashmap then _set will insert
 * this key-value pair into the appropriate bucket.
 */
#define HASH_MAP_SET(NAME, KEY_TYPE, DATA_TYPE)                                  \
  static inline void NAME##_set(struct NAME *map, KEY_TYPE key, DATA_TYPE val) { \
    DATA_TYPE *data = NAME##_find_ptr(map, key);                                 \
    if(data != NULL) {                                                           \
      *data = val;                                                               \
      return;                                                                    \
    }                                                                            \
    struct NAME##_entry k = {key, val};                                          \
    NAME##_bucket_push(&map->buckets[NAME##_get_bucket(key)], k);                \
  }

/**
 * _change_key replaces the key of a key-value pair with a new one, placing
 * it into the appropriate bucket.
 *
 * If there is no value with a given key in the map then this call will do nothing.
 */
#define HASH_MAP_CHANGE_KEY(NAME, KEY_TYPE, DATA_TYPE)                                             \
  static inline void NAME##_change_key(struct NAME *map, KEY_TYPE current_key, KEY_TYPE new_key) { \
    DATA_TYPE val;                                                                                 \
    if(NAME##_find(map, current_key, &val)) {                                                      \
      NAME##_remove(map, current_key);                                                             \
      NAME##_set(map, new_key, val);                                                               \
    }                                                                                              \
  }

/**
 * This macro creates a method which will delete any elements in the map which match a predicate.
 *
 * The delete callback is called once for every single element in the hashmap. If the callback
 * returns true for a given element then that element will be removed from the map.
 *
 * The post callback will be called after a method has been removed from the map, so that a cleanup
 * function may safely be called.
 */
#define HASH_MAP_DELETE_MATCHING(NAME, DATA_TYPE, BUCKETS)                                        \
  typedef bool (*NAME##_delete_callback_ptr_t)(struct NAME##_entry * v);                          \
  typedef void (*NAME##_post_delete_callback_ptr_t)(struct NAME##_entry * v);                     \
  static inline void NAME##_delete_matching(struct NAME *l, NAME##_delete_callback_ptr_t matches, \
                                            NAME##_post_delete_callback_ptr_t post) {             \
    for(size_t i = 0; i < BUCKETS; i++) {                                                         \
      NAME##_bucket_delete_matching(&l->buckets[i], matches, post);                               \
    }                                                                                             \
  }

/**
 * _count returns the total number of elements in the map.
 * This operation should be quite fast, looping for only BUCKETS
 * number of steps.
 */
#define HASH_MAP_COUNT(NAME, BUCKETS)                  \
  static inline size_t NAME##_count(struct NAME *l) {  \
    size_t sum_count = 0;                              \
    for(size_t i = 0; i < BUCKETS; i++) {              \
      sum_count += NAME##_bucket_size(&l->buckets[i]); \
    }                                                  \
    return sum_count;                                  \
  }

#define HASH_MAP_NUM_BUCKETS(NAME, BUCKETS)                 \
  static inline size_t NAME##_num_buckets(struct NAME *l) { \
    return BUCKETS;                                         \
  }

#define HASH_MAP(NAME, KEY_TYPE, DATA_TYPE, HASH_FN, CMP_FN, BUCKETS, BLOCK_SIZE) \
  HASH_MAP_TYPE(NAME, KEY_TYPE, DATA_TYPE, BUCKETS, BLOCK_SIZE);                  \
  HASH_MAP_INIT(NAME, BUCKETS)                                                    \
  HASH_MAP_FREE(NAME, BUCKETS)                                                    \
  HASH_MAP_GET_BUCKET(NAME, KEY_TYPE, BUCKETS, HASH_FN)                           \
  HASH_MAP_FIND_PTR(NAME, KEY_TYPE, DATA_TYPE, CMP_FN)                            \
  HASH_MAP_FIND(NAME, KEY_TYPE, DATA_TYPE, CMP_FN)                                \
  HASH_MAP_REMOVE(NAME, KEY_TYPE, CMP_FN)                                         \
  HASH_MAP_DELETE_MATCHING(NAME, DATA_TYPE, BUCKETS)                              \
  HASH_MAP_SET(NAME, KEY_TYPE, DATA_TYPE)                                         \
  HASH_MAP_CHANGE_KEY(NAME, KEY_TYPE, DATA_TYPE)                                  \
  HASH_MAP_NUM_BUCKETS(NAME, BUCKETS)                                             \
  HASH_MAP_COUNT(NAME, BUCKETS)

#endif
