#ifndef _HE_TEST_DISPATCH
#define _HE_TEST_DISPATCH

#include <stdarg.h>
#include <stdbool.h>

/**
 *  This function should NEVER be defined and only used in test files by
 *  #include "mock_fake_dispatch.h"
 */
void dispatch(char* func, ...);

bool dispatch_bool(char* func, ...);

#endif
