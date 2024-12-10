#include "tun.h"
#include "util.h"
#include <unistd.h>

int tun_alloc(char *dev, size_t dev_size, int flags) {
  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";
  if((fd = open(clonedev, O_RDWR)) < 0) {
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if(*dev) {
    safe_strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
  }

  if((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    return err;
  }

  safe_strncpy(dev, ifr.ifr_name, dev_size);

  return fd;
}

void write_to_tun(int tun_fd, uint8_t *buffer, int length) {
  // Can't write to tun before it's ready...
  if(tun_fd == 0) return;

  // Drop the packet if it exceeds our max MTU
  if(length > HE_MAX_OUTSIDE_MTU) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Packet was dropped since it exceeds max tunnel MTU");
    zlog_flush_buffer();
    return;
  }

  if(write(tun_fd, buffer, length) == -1) {
    // TODO: Report Err?
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error writing to TUN device");
    zlog_flush_buffer();
  }
}

ssize_t read_from_tun(int tun_fd, void *buf, size_t count) {
  return read(tun_fd, buf, count);
}
