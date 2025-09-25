//////////////////////////////////////////////////////////////////////
//
// SPDX-License-Identifier: MIT
//
// bloom-filter.h
// --------------
//
// A configurable, header-only implementation of bloom filters in C99
// with no dependencies.
//
// Author: Giovanni Santini
// Mail: giovanni.santini@proton.me
// License: MIT
//
//
// Documentation
// -------------
//
// A Bloom filter is a space-efficient probabilistic data structure
// that is used to test whether an element is a member of a set. False
// positives are possible, but false negatives are not — meaning it
// may report that an element is present when it is not, but it will
// never miss an element that was actually inserted.
//
// Internally, the filter uses a bit array and multiple independent
// hash functions.  When an element is added, each hash function maps
// it to a position in the bit array, and those bits are set. To check
// membership, the same hash functions are applied: if all
// corresponding bits are set, the element is *possibly* in the set;
// if any bit is not set, the element is definitely not in the set.
//
// Advantages:
//  - Extremely memory efficient for large sets
//  - Fast insert and query operations
//
// Limitations:
//  - Does not support removal of elements (in standard form)
//  - Allows false positives with a probability depending on filter
//    size and usage
//
//
// Usage
// -----
//
// Do this:
//
//   #define BLOOM_FILTER_IMPLEMENTATION
//
// before you include this file in *one* C or C++ file to create the
// implementation.
//
// i.e. it should look like this:
//
//   #include ...
//   #include ...
//   #include ...
//   #define BLOOM_FILTER_IMPLEMENTATION
//   #include "bloom-filter.h"
//
// You can tune the library by #defining certain values. See the
// "Config" comments under "Configuration" below.
//
// You need to initialize a filter with `bloom_init` and eventually
// destroy it with `bloom_destroy`. To register a value, use
// `bloom_register`. To check if a value is in the bloom filter, use
// `bloom_check`. See the function definitions for more information.
//
// Check some examples at the end of the header
//
//
// Code
// ----
//
// The official git repository of bloom-filter.h is hosted at:
//
//     https://github.com/San7o/bloom-filter.h
//
// This is part of a bigger collection of header-only C99 libraries
// called "micro-headers", contributions are welcome:
//
//     https://github.com/San7o/micro-headers
//

#ifndef _BLOOM_FILTER_H_
#define _BLOOM_FILTER_H_

#define BLOOM_FILTER_VERSION_MAJOR 0
#define BLOOM_FILTER_VERSION_MINOR 1

#ifdef __cplusplus
extern "C" {
#endif

//
// Configuration
//

// Config: The default size of the bloom filter
#ifndef BLOOM_FILTER_SIZE
  #define BLOOM_FILTER_SIZE 1024
#endif

// Config: The default number of bloom hashes to compute
#ifndef BLOOM_FILTER_NUMBER_OF_HASHES
  #define BLOOM_FILTER_NUMBER_OF_HASHES 3
#endif

// Config: The type of an hash
#ifndef BLOOM_FILTER_HASH_T
  #define BLOOM_FILTER_HASH_T unsigned int
#endif

// Config: The type of an hash key
#ifndef BLOOM_FILTER_HASH_INPUT_T
  #define BLOOM_FILTER_HASH_INPUT_T char*
#endif

// Config: The memory allocator.
//
// Note: The allocator should accept the same arguments of calloc(3),
// and set to memory region to 0. Default function is calloc from
// stdlib.
#ifndef BLOOM_FILTER_CALLOC
  #include <stdlib.h>
  #define BLOOM_FILTER_CALLOC calloc
#endif

// Config: The function to free allocated memory.
//
// Note: The function should accept only a pointer to memory. Default
// function is free(3) from stdlib.
#ifndef BLOOM_FILTER_FREE
  #include <stdlib.h>
  #define BLOOM_FILTER_FREE free
#endif

//
// Errors
//

typedef int bloom_error;
#define BLOOM_OK                          0
#define BLOOM_ERROR_FILTER_NULL          -1
#define BLOOM_ERROR_FILTER_UNINITIALIZED -2
#define BLOOM_ERROR_ALLOCATION_FAILED    -3
#define _BLOOM_ERROR_MAX                 -4

//
// Types
//

// Booleans
#ifndef bool
  #define bool _Bool
#endif
#ifndef true
  #define true 1
#endif
#ifndef false
  #define false 0
#endif

typedef BLOOM_FILTER_HASH_T bloom_hash_t;
typedef BLOOM_FILTER_HASH_INPUT_T bloom_hash_input_t;
  
// An hash function
//
// Args:
//  - arg1: the input to hash
//  - arg2: the size of the input. May be ignored depending on the
//          implementation.
//
// Returns: A bloom_hash_t hash
typedef bloom_hash_t (*bloom_hash_func_t)(bloom_hash_input_t, unsigned int);

// A memory allocator.
//
// Args: See calloc(3)
// Return: See calloc(3)
//
// Note: The allocator should set the memory to 0, like calloc(3)
typedef void (*bloom_allocator_t)(size_t, size_t);

// A bloom filter
typedef struct {
  bool *_array;
  // the size of _array
  unsigned int size;
  // An hash function
  bloom_hash_func_t hash1;
  // Another hash function (should be different from hash1)
  bloom_hash_func_t hash2;
  // The number of hashes to calculate, this is often referred to as
  // "k". hash1 and hash2 will be combined to generate other hashes,
  // see the implementation for more information.
  unsigned int number_of_hashes;
} bloom_filter_t;

//
// Function declarations
//

// Initialize the bloom filter with specified fields, allocates memory.
//
// Args:
//  - bloom_filter: a pointer to the filter that needs initialization
//  - other args: fields to set in bloom_filter
//
// Returns: 0 on success, or a negative error
//
// Notes: A default value will be set to all the unspecified fields.
// Remember to call bloom_destroy after you are done with the filter.
//
// Example:
// bloom_filter_t my_filter;
// bloom_init(&my_filter, .size = 10, .number_of_hashes = 5);
#define bloom_init(bloom_filter, ...) _bloom_init_impl(             \
    bloom_filter,                                                   \
    &(bloom_filter_t){                                              \
      ._array   = NULL,                                             \
      .size     = BLOOM_FILTER_SIZE,                                \
      .hash1    = bloom_hash1,                                      \
      .hash2    = bloom_hash2,                                      \
      .number_of_hashes = BLOOM_FILTER_NUMBER_OF_HASHES,            \
      __VA_ARGS__                                                   \
    })

// Initialize a bloom filter with optional settings, allocates memory.
//
// Args:
//  - bloom_filter: a pointer to the filter than needs initialization
//  - bloom_filter_settings: If non NULL, this will be copied to
//                           bloom_filter.
//
// Returns: 0 on success, or a negative error
//
// Notes: Remember to call bloom_destroy after you are done with the
// filter.
// See macro bloom_init for usage.
bloom_error _bloom_init_impl(bloom_filter_t *bloom_filter,
                             bloom_filter_t *bloom_filter_settings);

// Destroy the filter.
//
// Args:
//  - bloom_filter: pointer to the filter to destroy
//
// Returns: 0 on success, or a negative error
//
// Notes: Should always be called if the filter was initialized with
// bloom_init.
bloom_error bloom_destroy(bloom_filter_t *bloom_filter);

// Register an element in the bloom filter
//
// Args:
//  - bloom_filter: pointer to the bloom filter
//  - input: the input of the bloom filter
//  - input_len: the length of the input
//
// Returns: 0 on success, or a negative error
bloom_error bloom_register(bloom_filter_t *bloom_filter,
                           bloom_hash_input_t input,
                           unsigned int input_len);

// Check whether a value is registered in a bloom filter
//
// Args:
//  - bloom_filter: pointer to the bloom filter
//  - input: the input of the bloom filter
//  - input_len: the length of the input
//
// Returns: true (1) if value with input is found, false (0) if the input
// was not found, or a negative bloom_error in case of failure.
int bloom_check(bloom_filter_t *bloom_filter,
                bloom_hash_input_t input,
                unsigned int input_len);

// Merge the second bloom filter into the first
//
// Args:
//  - bloom_filter_dest: the bloom filter that be updated
//  - bloom_filter_src: the bloom filter that will be merged
//
// Returns: 0 on success, or a negative error
bloom_error bloom_merge(bloom_filter_t *bloom_filter_dest,
                        bloom_filter_t *bloom_filter_src);

// Hash [bytes] of size [len]
//
// Args:
//  - input: an hash input
//  - input_len: the length of the hash input
//
// Returns: the hashed value of the input
bloom_hash_t bloom_hash1(bloom_hash_input_t input,
                         unsigned int input_len);

// Hash [bytes] of size [len]
//
// Args:
//  - input: an hash input
//  - input_len: the length of the hash input
//
// Returns: the hashed value of the input
bloom_hash_t bloom_hash2(bloom_hash_input_t input,
                         unsigned int input_len);

// Get the error as a string
//
// Args:
//  - error: the error to convert
//
// Returns: The string description of the error
const char* bloom_error_string(bloom_error error);

//
// Implementation
//

#ifdef BLOOM_FILTER_IMPLEMENTATION

bloom_error _bloom_init_impl(bloom_filter_t *bloom_filter,
                             bloom_filter_t *bloom_filter_settings)
{
  if (bloom_filter == NULL)
    return BLOOM_ERROR_FILTER_NULL;

  if (bloom_filter_settings != NULL)
    *bloom_filter = *bloom_filter_settings;

  if (bloom_filter->size == 0)
    return BLOOM_OK;

  bloom_filter->_array = BLOOM_FILTER_CALLOC(bloom_filter->size,
                                             sizeof(bool));
  if (bloom_filter->_array == NULL)
    return BLOOM_ERROR_ALLOCATION_FAILED;

  return BLOOM_OK;
}

bloom_error bloom_destroy(bloom_filter_t *bloom_filter)
{
  if (bloom_filter == NULL)
    return BLOOM_ERROR_FILTER_NULL;

  if (bloom_filter->_array == NULL)
    return BLOOM_OK;

  BLOOM_FILTER_FREE(bloom_filter->_array);
  
  return BLOOM_OK;
}

bloom_error bloom_register(bloom_filter_t *bloom_filter,
                           bloom_hash_input_t input,
                           unsigned int input_len)
{
  if (bloom_filter == NULL)
    return BLOOM_ERROR_FILTER_NULL;

  if (bloom_filter->_array == NULL)
    return BLOOM_ERROR_FILTER_UNINITIALIZED;

  for (unsigned int i = 0; i < bloom_filter->number_of_hashes; ++i)
  {
    bloom_hash_t hash1 = bloom_filter->hash1(input, input_len);
    bloom_hash_t hash2 = bloom_filter->hash2(input, input_len);
    
    // Kirsch-Mitzenmacher-Optimization
    // https://www.eecs.harvard.edu/~michaelm/postscripts/tr-02-05.pdf
    bloom_hash_t hash = hash1 + i * hash2;
    bloom_filter->_array[hash % bloom_filter->size] = true;
  }
  
  return BLOOM_OK;
}


int bloom_check(bloom_filter_t *bloom_filter,
                bloom_hash_input_t input,
                unsigned int input_len)
{
  if (bloom_filter == NULL)
    return BLOOM_ERROR_FILTER_NULL;

  if (bloom_filter->_array == NULL)
    return BLOOM_ERROR_FILTER_UNINITIALIZED;

  bool present = true;
  for (unsigned int i = 0; i < bloom_filter->number_of_hashes; ++i)
  {
    bloom_hash_t hash1 = bloom_filter->hash1(input, input_len);
    bloom_hash_t hash2 = bloom_filter->hash2(input, input_len);
    
    // Kirsch-Mitzenmacher-Optimization
    // https://www.eecs.harvard.edu/~michaelm/postscripts/tr-02-05.pdf
    bloom_hash_t hash = hash1 + i * hash2;
    present &= bloom_filter->_array[hash % bloom_filter->size];
    if (!present)
      return false;
  }

  return true;
}

bloom_error bloom_merge(bloom_filter_t *bloom_filter_dest,
                        bloom_filter_t *bloom_filter_src)
{
  if (bloom_filter_dest == NULL
      || bloom_filter_src == NULL)
    return BLOOM_ERROR_FILTER_NULL;

  if (bloom_filter_dest->_array == NULL
      || bloom_filter_src->_array == NULL)
    return BLOOM_ERROR_FILTER_UNINITIALIZED;

  for (unsigned int i = 0; i < bloom_filter_src->size; ++i)
  {
    if (bloom_filter_src->_array[i])
      bloom_filter_dest->_array[i % bloom_filter_dest->size] = true;
  }
  
  return BLOOM_OK;
}

// Credits to http://www.cse.yorku.ca/~oz/hash.html
unsigned int bloom_hash_djb2(const char *bytes, unsigned int input_len)
{
  unsigned int hash = 5381;
  for (unsigned int i = 0; i < input_len; ++i)
  {
    hash = ((hash << 5) + hash) + bytes[i]; /* hash * 33 + c */
  }
  return hash;
}

// Credits to http://www.cse.yorku.ca/~oz/hash.html
unsigned int bloom_hash_sdbm(const char *bytes, unsigned int input_len)
{
  unsigned int hash = 0;
  for (unsigned int i = 0; i < input_len; ++i)
  {
    hash = bytes[i] + (hash << 6) + (hash << 16) - hash;
  }
  
  return hash;
}

bloom_hash_t bloom_hash1(bloom_hash_input_t input,
                         unsigned int input_len)
{
  return bloom_hash_djb2(input, input_len);
}

bloom_hash_t bloom_hash2(bloom_hash_input_t input,
                         unsigned int input_len)
{
  return bloom_hash_sdbm(input, input_len);
}

#if _BLOOM_ERROR_MAX != -4
#error "Updated bloom errors, maybe should update bloom_error_string"
#endif
const char* bloom_error_string(bloom_error error)
{
  if (error >= 0)
    return "BLOOM_OK";
  switch(error)
  {
  case BLOOM_ERROR_FILTER_NULL:
    return "ERROR_FILTER_NULL";
  case BLOOM_ERROR_FILTER_UNINITIALIZED:
    return "ERROR_FILTER_UNINITIALIZED";
  case BLOOM_ERROR_ALLOCATION_FAILED:
    return "ERROR_ALLOCATION_FAILED";
  default:
    break;
  }
  return "ERROR_UNKNOWN";
}

#endif // BLOOM_FILTER_IMPLEMENTATION

//
// Example
//

#if 0
#define BLOOM_FILTER_IMPLEMENTATION
#include "bloom-filter.h"

#include <assert.h>

int main(void)
{
  bloom_filter_t filter;
  /* Initialize */
  assert(bloom_init(&filter, .size = 1024, .number_of_hashes = 4) == BLOOM_OK);

  /* Register something */
  assert(bloom_register(&filter, "test", 4) == BLOOM_OK);

  assert(bloom_check(&filter, "hello", 4) == 0);
  assert(bloom_check(&filter, "test", 4) == 1);
  assert(bloom_check(&filter, "nothing here", 12) == 0);
  assert(bloom_check(&filter, "uyeihkjdbhakjhdsjah", 19) == 0);
  assert(bloom_check(&filter, "foobar", 6) == 0);

  /* Register something else */
  assert(bloom_register(&filter, "foobar", 6) == BLOOM_OK);
  
  assert(bloom_check(&filter, "foobar", 6) == 1);

  /* Cleanup */
  assert(bloom_destroy(&filter) == BLOOM_OK);  
  return 0;
}
#endif // 0

#ifdef __cplusplus
}
#endif

#endif // _BLOOM_FILTER_H_
