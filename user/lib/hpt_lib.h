#ifndef HPT_LIB_H
#define HPT_LIB_H

#include <stdint.h>
#include <stddef.h>  // For size_t
#include <sys/types.h>  // For ssize_t

#ifdef __KERNEL__
#define ACQUIRE(src) smp_load_acquire((src))
#else
#define ACQUIRE(src) __atomic_load_n((src), __ATOMIC_ACQUIRE)
#endif

#ifdef __KERNEL__
#define STORE(dst, val) smp_store_release((dst), (val))
#else
#define STORE(dst, val) __atomic_store_n((dst), (val), __ATOMIC_RELEASE)
#endif

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
	int ready_flag_rx;
	int ready_flag_tx;
	int size;
}hpt_data_info_t;

typedef struct hpt_dma_buffer {
	void *data_combined;              
} hpt_dma_buffer_t;

struct hpt {
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


// Returns the file descriptor of the HPT device.
int hpt_fd(struct hpt *dev);

// Initializes the HPT device and opens the file descriptor.
int hpt_init();

// Allocates and configures the HPT device structure and buffers.
struct hpt *hpt_alloc(const char name[HPT_NAMESIZE], size_t num_ring_items);

// Closes the HPT device and frees allocated resources.
void hpt_close(struct hpt *dev);

// Reads data from the HPT device buffers.
void hpt_read(struct hpt *dev, hpt_buffer_t *buf);

// Writes data to the HPT device buffers.
void hpt_write(struct hpt *dev, hpt_buffer_t *buf);


#define HPT_IOCTL_CREATE _IOWR(0x92, 1, struct hpt_net_device_info)

#define HPT_DEVICE "hpt"

#endif // HPT_LIB_H