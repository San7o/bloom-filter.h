// SPDX-License-Identifier: MIT

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
