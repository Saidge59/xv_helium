#include "stub_pkt_maker.h"

#include <stdio.h>
#include <string.h>

test_packet *fake_empty_packet() {
  test_packet *pkt = jecalloc(1, sizeof(test_packet));
  // Yes this should always be 0 but just making it explicit
  pkt->len = 0;
  return pkt;
}

test_packet *fake_string_packet(char *str) {
  size_t bytelen = strlen(str) + 1;

  test_packet *pkt = jecalloc(1, sizeof(test_packet) + bytelen);

  pkt->len = bytelen;
  memcpy(pkt->data, str, bytelen);

  return pkt;
}
