#ifndef TUN_H
#define TUN_H
#include <linux/if.h>
#include <linux/if_tun.h>

#include "helium.h"

int tun_alloc(char *dev, size_t dev_size, int flags);
void write_to_tun(int tun_fd, uint8_t *buffer, int length);

// A convenience function to allow us to abstract away the read system call for testing
ssize_t read_from_tun(int tun_fd, void *buf, size_t count);

#endif  // TUN_H
