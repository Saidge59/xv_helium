#include "unity.h"
#include "util.h"

// Workaround to get statsd code
#include "statsd-client.c"

void test_statsd_max_chars() {
  // Build a mock statsd server
  int sockfd;
  struct sockaddr_in servaddr, statsdaddr;
  char buffer[512];

  memset(&servaddr, 0, sizeof(servaddr));
  memset(&statsdaddr, 0, sizeof(statsdaddr));

  if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    TEST_FAIL();
  }

  servaddr.sin_family = AF_INET;  // IPv4
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(8125);

  // Bind the socket with the server address
  if(bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    TEST_FAIL();
  }

  // Send the stat
  statsd_link *statsd = statsd_init_with_namespace_tags(
      "127.0.0.1", 8125, "helium",
      "this-is-an-extremely-long-tag-for-use-in-ensuring-that-our-tag-length-is-sufficient");
  statsd_inc(statsd, "this-is-a-giant-fake-stat", 1.0f);

  // Receive stat data
  socklen_t len;
  ssize_t n;

  len = sizeof(statsdaddr);

  n = recvfrom(sockfd, (char *)buffer, 512, MSG_WAITALL, (struct sockaddr *)&statsdaddr, &len);
  buffer[n] = '\0';

  close(sockfd);
  statsd_finalize(statsd);

  // Verify stat data
  TEST_ASSERT_GREATER_THAN(100, strlen(buffer));
  TEST_ASSERT_EQUAL_STRING(
      "helium.this-is-a-giant-fake-stat:1|c|#this-is-an-extremely-long-tag-for-use-in-ensuring-"
      "that-our-tag-length-is-sufficient",
      buffer);
}
