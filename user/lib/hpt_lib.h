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

typedef struct hpt_data_info {
  int in_use;
	size_t size;
	int ready_flag_rx;
	int ready_flag_tx;
}hpt_data_info_t;

typedef struct hpt_dma_buffer {
	void *data_combined;              
  int in_use;
} hpt_dma_buffer_t;

struct hpt {
    //void *mapped_buffer;
    hpt_dma_buffer_t buffers[HPT_BUFFER_COUNT];
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
int message(hpt_data_info_t *data_info);
int check_time(hpt_data_info_t *data_info);

#define HPT_IOCTL_CREATE _IOWR(0x92, 1, struct hpt_net_device_info)
#define HPT_IOCTL_NOTIFY _IO(0x92, 2)

#define HPT_DEVICE "hpt"

#endif // HPT_LIB_H