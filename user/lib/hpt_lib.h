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

typedef struct hpt_handle {
    int fd;
    void *mapped_buffer;
    struct ring_buffer *ring_tx;
    struct ring_buffer *ring_rx;
} hpt_handle_t;

hpt_handle_t *hpt_open(void);
int hpt_close(hpt_handle_t *handle);
void hpt_send(hpt_handle_t *handle);
ssize_t hpt_read(hpt_handle_t *handle, void *buf, size_t count);
void hpt_write(hpt_handle_t *handle);

#define HPT_IOCTL_CREATE _IO(0x92, 1)
#define HPT_IOCTL_NOTIFY _IO(0x92, 2)

#define HPT_BUFFER_SIZE 2048
#define HPT_NUM_BUFFERS 1024
#define HPT_ALLOC_SIZE (HPT_BUFFER_SIZE * HPT_NUM_BUFFERS)

#endif // HPT_LIB_H