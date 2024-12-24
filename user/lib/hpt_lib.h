#ifndef HPT_LIB_H
#define HPT_LIB_H

#include <stdint.h>
#include <stddef.h>  // For size_t
#include <sys/types.h>  // For ssize_t

#define HPT_NAMESIZE 32

struct ring_buffer {
    uint32_t write_index;
    uint32_t read_index;
    //uint32_t num_buffers;
    //uint32_t buffer_size;
};

struct hpt {
    void *mapped_buffer;
    struct ring_buffer *ring_tx;
    struct ring_buffer *ring_rx;
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
void message(hpt_buffer_t *buf);

#define HPT_IOCTL_CREATE _IO(0x92, 1)
#define HPT_IOCTL_NOTIFY _IO(0x92, 2)

#define HPT_DEVICE "hpt"

#define HPT_BUFFER_SIZE 2048
#define HPT_NUM_BUFFERS 1024
#define HPT_ALLOC_SIZE (HPT_BUFFER_SIZE * HPT_NUM_BUFFERS)

#endif // HPT_LIB_H