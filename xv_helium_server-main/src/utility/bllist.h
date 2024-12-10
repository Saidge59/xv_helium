/** Taken from https://github.com/jawline/blakec **/
#ifndef _BLAKE_LIST_H_
#define _BLAKE_LIST_H_
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <jemalloc.h>

/**
 * This can be overwritten to set custom behaviour when an illegal array index is used.
 * If overwritten with a return statement users can set a 'default' behaviour for requests
 * on elements not in the list.
 * When overriding, either return a value or terminate, otherwise the list will be in an undefined
 * state.
 */
/// Example override: #define LIST_ILLEGAL_OP(msg) return 0;
#ifndef LIST_ILLEGAL_OP
#define LIST_ILLEGAL_OP(msg)                                            \
  fprintf(stderr, "Exit because of illegal list operation: %s\n", msg); \
  exit(EXIT_FAILURE);
#endif

#ifndef LIST_ILLEGAL_CONCAT
#define LIST_ILLEGAL_CONCAT(msg)                                            \
  fprintf(stderr, "Exit because of illegal list concatenation: %s\n", msg); \
  exit(EXIT_FAILURE);
#endif

/**
 * Dynamically allocated array structure.
 * The DYNAMIC_ARRAY macro declares a new data structure
 * to act as a dynamically allocated array.
 *
 * The array amortises allocation cost, which means that each
 * array expansion which requires a re-allocation doubles the
 * capacity of the array.
 *
 * This is a useful property because arrays larger
 * than the initial allocation size grown linearly will require
 * frequent reallocation, but grown non-linearly (i.e, doubled in size)
 * will require fewer, and re-allocation is one of the most significant
 * costs in array management.
 *
 * Further, arrays that grow and shrink on linear bounds may have
 * poor performance properties in-practice because the use-case steps
 * a small number of increments over the grow/shrink threshold.
 * For example, if we have an array of length 10 that grows with every 2
 * operations, then a procedure which grows and then shrinks the list by 3
 * elements will require re-allocations. This is less likely when the
 * list grows non-linearly.
 *
 * NOTE: We store shrink_at in the struct rather than computing it to reduce the cost of checking
 */
#define DYNAMIC_ARRAY_TYPE(NAME, TYPE)                               \
  typedef struct NAME {                                              \
    /* The backing array */                                          \
    TYPE *data;                                                      \
    /* The current number of elements in the array */                \
    size_t current;                                                  \
    /* The capacity of the current array without a re-allocation */  \
    size_t capacity;                                                 \
    /* The number of elements at which the array should be shrunk */ \
    size_t shrink_at;                                                \
  } NAME##_t;

/**
 * _init places the dynamic array in a state where
 * elements can be added.
 * NOTE: _init must be called before the array can be used.
 */
#define DYNAMIC_ARRAY_INIT(NAME, TYPE, SIZE)        \
  static void NAME##_init(struct NAME *l) {         \
    memset(l, 0, sizeof(struct NAME));              \
    l->capacity = SIZE;                             \
    l->shrink_at = 0;                               \
    l->data = jemalloc(sizeof(TYPE) * l->capacity); \
    l->current = 0;                                 \
  }

/**
 * _free frees any memory allocated by the array structures.
 * NOTE: If DATA_TYPE is a pointer it not free the memory pointed at, only
 * the memory used to store the pointers in a list.
 */
#define DYNAMIC_ARRAY_FREE(NAME)            \
  static void NAME##_free(struct NAME *l) { \
    jefree(l->data);                        \
    memset(l, 0, sizeof(struct NAME));      \
  }

/**
 * INTERNAL USE MACRO: DO NOT USE
 * This macro adjusts the shrink size after the array has changed in capacity.
 */
#define DYNAMIC_ARRAY_ADJUST_SHRINK(LISTVAR, NAME, TYPE, SIZE)         \
  /* We only shrink an array up to the user specified minimum size. */ \
  /* If shrink_at is zero the array will never be shrunk */            \
  if(LISTVAR->capacity > SIZE) {                                       \
    LISTVAR->shrink_at = (LISTVAR->capacity / 3);                      \
  } else {                                                             \
    LISTVAR->shrink_at = 0;                                            \
  }

/**
 * INTERNAL CALL: Method to increase the size of the array
 * _increase chooses an amount to increase the capacity of the
 * array by (currently, doubles capacity) and then reallocates the
 * array so that we have space.
 */
#define DYNAMIC_ARRAY_INCREASE(NAME, TYPE, SIZE)                              \
  static inline void NAME##_increase(struct NAME *l) {                        \
    /* Increase doubles capacity */                                           \
    l->capacity += l->capacity;                                               \
    DYNAMIC_ARRAY_ADJUST_SHRINK(l, NAME, TYPE, SIZE)                          \
    /* After deciding on the new capacity we re-allocate the backing array */ \
    TYPE *new_data = jerealloc(l->data, sizeof(TYPE) * l->capacity);          \
    l->data = new_data;                                                       \
  }

/**
 * INTERNAL CALL: Method to shrink the array
 * At a given threshold we shrink the array automatically.
 * We attempt to half the allocated memory for the array.
 * If the array would be smaller than SIZE, the minimum size of the array,
 * then we set the capacity to SIZE.
 * Amortised cost: Half array size if array consumption drops below 30%
 */
#define DYNAMIC_ARRAY_SHRINK(NAME, TYPE, SIZE)                  \
  static inline void NAME##_shrink(struct NAME *l) {            \
    if(l->shrink_at && l->current <= l->shrink_at) {            \
      l->capacity /= 2;                                         \
      if(l->capacity < SIZE) {                                  \
        l->capacity = SIZE;                                     \
      }                                                         \
      l->data = jerealloc(l->data, l->capacity * sizeof(TYPE)); \
      DYNAMIC_ARRAY_ADJUST_SHRINK(l, NAME, TYPE, SIZE)          \
    }                                                           \
  }

/**
 * _push adds an element to the end of the array, expanding the
 * arrays capacity to fit the element if necessary.
 */
#define DYNAMIC_ARRAY_PUSH(NAME, TYPE)                     \
  static inline void NAME##_push(struct NAME *l, TYPE v) { \
    if(l->current >= l->capacity) {                        \
      NAME##_increase(l);                                  \
    }                                                      \
    *(l->data + l->current) = v;                           \
    l->current += 1;                                       \
  }

/**
 * _remove removes an array item at a given index, returns it, and shrinks the array if necessary.
 * WARNING: Expensive. If possible POP instead
 * WARNING: Every index after index i is shifted left one place
 */
#define DYNAMIC_ARRAY_REMOVE(NAME, TYPE)                                                \
  static inline TYPE NAME##_remove(struct NAME *l, size_t index) {                      \
    if(index >= l->current) {                                                           \
      LIST_ILLEGAL_OP("remove index out of bounds");                                    \
    }                                                                                   \
    l->current -= 1;                                                                    \
    TYPE r = l->data[index];                                                            \
    memmove(&l->data[index], &l->data[index + 1], sizeof(TYPE) * (l->current - index)); \
    NAME##_shrink(l);                                                                   \
    return r;                                                                           \
  }

/**
 * _pop deletes the element at the end of the array, returns it, and
 * shrinks the array if necessary.
 * This has very low cost, and should be used whenever possible.
 */
#define DYNAMIC_ARRAY_POP(NAME, TYPE)             \
  static inline TYPE NAME##_pop(struct NAME *l) { \
    if(l->current == 0) {                         \
      LIST_ILLEGAL_OP("pop an empty list");       \
    }                                             \
    l->current -= 1;                              \
    TYPE r = l->data[l->current];                 \
    NAME##_shrink(l);                             \
    return r;                                     \
  }

/**
 * _delete deletes any elements in the array which match a predicate, and calls
 * an optional post callback after it is removed.
 *
 * We loop once through every element.
 * If that element matches a callback, we remove it (shifting all elements left one place)
 * If that element does not match then we increment the loop index by one
 * If an element is deleted, we will call the post callback.
 * If the post callback is NULL we ignore it.
 *
 * The delete method deletes any value for which the supplied callback method returns true
 * The callback method takes TYPE* and returns true/false.
 */
#define DYNAMIC_ARRAY_DELETE_MATCHING(NAME, TYPE)                                                 \
  typedef bool (*NAME##_delete_callback_ptr_t)(TYPE * v);                                         \
  typedef void (*NAME##_post_delete_callback_ptr_t)(TYPE * v);                                    \
  static inline void NAME##_delete_matching(struct NAME *l, NAME##_delete_callback_ptr_t matches, \
                                            NAME##_post_delete_callback_ptr_t post) {             \
    size_t idx = 0;                                                                               \
    while(idx < l->current) {                                                                     \
      if(matches(&l->data[idx])) {                                                                \
        TYPE nval = l->data[idx];                                                                 \
        NAME##_remove(l, idx);                                                                    \
        if(post) {                                                                                \
          post(&nval);                                                                            \
        }                                                                                         \
      } else {                                                                                    \
        idx++;                                                                                    \
      }                                                                                           \
    }                                                                                             \
  }

/**
 * _concat concatenates the second array into the first. The second array
 * is not free'd and can continue to be used afterwards.
 *
 * We leave a small amount of space (SIZE) after the concatenated array for further
 * expansion.
 */
#define DYNAMIC_ARRAY_CONCAT(NAME, TYPE, SIZE)                              \
  static inline void NAME##_concat(struct NAME *l1, struct NAME *l2) {      \
    if(!l1 || !l1->data || !l2 || !l2->data) {                              \
      LIST_ILLEGAL_CONCAT("invalid pointer to list or uninitialized list"); \
    }                                                                       \
    l1->capacity = (l1->current + l2->current) + SIZE;                      \
    l1->data = jerealloc(l1->data, sizeof(TYPE) * l1->capacity);            \
    memcpy(l1->data + l1->current, l2->data, l2->current * sizeof(TYPE));   \
    l1->current += l2->current;                                             \
    DYNAMIC_ARRAY_ADJUST_SHRINK(l1, NAME, TYPE, SIZE);                      \
  }

/**
 * _size returns the number of elements currently in
 * the array (NOTE: This is not the array capacity)
 */
#define DYNAMIC_ARRAY_SIZE(NAME)                     \
  static inline size_t NAME##_size(struct NAME *l) { \
    return l->current;                               \
  }

#define DYNAMIC_ARRAY(name, type, block_size)    \
  DYNAMIC_ARRAY_TYPE(name, type);                \
  DYNAMIC_ARRAY_INIT(name, type, block_size)     \
  DYNAMIC_ARRAY_FREE(name)                       \
  DYNAMIC_ARRAY_INCREASE(name, type, block_size) \
  DYNAMIC_ARRAY_PUSH(name, type)                 \
  DYNAMIC_ARRAY_SHRINK(name, type, block_size)   \
  DYNAMIC_ARRAY_POP(name, type)                  \
  DYNAMIC_ARRAY_CONCAT(name, type, block_size)   \
  DYNAMIC_ARRAY_REMOVE(name, type)               \
  DYNAMIC_ARRAY_SIZE(name)                       \
  DYNAMIC_ARRAY_DELETE_MATCHING(name, type)

#endif
