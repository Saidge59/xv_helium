#ifndef HPT_LIB_H
#define HPT_LIB_H

#include <stdint.h>
#include <stddef.h>  // For size_t
#include <sys/types.h>  // For ssize_t

#define HPT_NAMESIZE 32
#define HPT_BUFFER_COUNT 65535
#define HPT_BUFFER_SIZE 4096
#define HPT_NUM_BUFFERS 1024

struct hpt_net_device_info {
	char name[HPT_NAMESIZE];
	size_t ring_buffer_items;
};

struct hpt {
    //void *mapped_buffer;
    void *mapped_buffer; 
    size_t ring_buffer_items;
};

int hpt_fd(struct hpt *dev);

typedef struct hpt_buffer {
  char *base;
  size_t capacity;
  size_t len;
} hpt_buffer_t;

hpt_buffer_t* hpt_get_tx_buffer();

int hpt_init();
struct hpt *hpt_alloc(const char name[HPT_NAMESIZE], size_t num_ring_items);
void hpt_close(struct hpt *dev);
void hpt_write(struct hpt *dev, hpt_buffer_t *buf);
void hpt_read(struct hpt *dev, hpt_buffer_t *buf);
void message(void *buf);

#define HPT_IOCTL_CREATE _IOWR(0x92, 1, struct hpt_net_device_info)
#define HPT_IOCTL_NOTIFY _IO(0x92, 2)

#define HPT_DEVICE "hpt"

#endif // HPT_LIB_H