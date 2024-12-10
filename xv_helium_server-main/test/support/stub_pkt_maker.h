#ifndef STUB_PKT_MAKER
#define STUB_PKT_MAKER

#include "helium.h"

#include "bllist.h"

typedef struct test_packet {
  size_t len;
  uint8_t data[];
} test_packet;

test_packet *fake_empty_packet();

test_packet *fake_string_packet(char *str);

#endif
