#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <sys/mman.h>

#include "hpt.h"

struct hpt {
	char name[HPT_NAMESIZE];

	/* Callbacks to be called on incoming packets */
	hpt_do_pkt read_cb;

	/* The supplied read handle, this is given to read_cb so it can recover it's context */
	void *read_hdl;

	/* Ring buffers userspace address pointers */
	size_t rb_size;

	/* The metadata for the transmit ring */
	struct hpt_ring_buffer *tx_ring;

	/* The metadata for the receive ring */
	struct hpt_ring_buffer *rx_ring;

	/* The start of the transmit ring data in memory */
	uint8_t *tx_start;

	/* The start of the receive ring data in memory */
	uint8_t *rx_start;

	/* The ring memory location for munmap */
	void *ring_memory;

	/* The ring memory size for munmap */
	size_t ring_memory_size;

	uint8_t *kthread_needs_wake;
};

static volatile int hpt_fd = -1;
void *in_buffer;
void *out_buffer;

int hpt_wake_fd()
{
	return hpt_fd;
}

int hpt_init()
{
	if (hpt_fd < 0) {
		hpt_fd = open("/dev/" HPT_DEVICE, O_RDWR);
		if (hpt_fd < 0) {
			printf("HPT: Err: %i\n", hpt_fd);
			return -1;
		}
	}

	return 0;
}

void *map_buffers(int fd, int buffer_idx) {
    void *mapped;
	long page_size = sysconf(_SC_PAGESIZE);  // Узнаём размер страницы
    if (page_size == -1) {
        perror("Failed to get page size");
        return NULL;
    }
	
	printf("page_size: %ld\n", page_size);

    mapped = mmap(NULL, HPT_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, buffer_idx * page_size);
    if (mapped == MAP_FAILED) {
        perror("Failed to mmap buffers");
        return NULL;
    }

    return mapped;
}

struct hpt *hpt_alloc(const char name[HPT_NAMESIZE], size_t buffer_items_count,
		      hpt_do_pkt read_cb, void *handle, size_t idle_usec)
{
	int ret;
	struct hpt_network_device_info dev_info;
	struct hpt *hpt = NULL;

	if (!name || !buffer_items_count) {
		return NULL;
	}

	/* Check if HPT subsystem has been initialized */
	if (hpt_fd < 0) {
		printf("HPT: is not initialized. try again\n");
		return NULL;
	}

	if (buffer_items_count > HPT_MAX_ITEMS) {
		printf("HPT: hpt rings only support up to %u ring buffer items\n",
		       HPT_MAX_ITEMS);
		return NULL;
	}
/*
	ret = ioctl(hpt_fd, HPT_IOCTL_ALLOCATE, NULL);
	if (ret < 0) {
		goto error;
	}
*/
	printf("HPT: Mapping in the memory\n");

	size_t mem_size = (2 * sizeof(struct hpt_ring_buffer)) +
			  (2 * hpt_rb_ring_buffer_stride(buffer_items_count)) + sizeof(uint8_t);

/*
	uint8_t *wake_flag = mapped_region + mem_size - sizeof(uint8_t);

	printf("HPT: Mapped memory into userspace at %p\n", mapped_region);
*/
	memset(&dev_info, 0, sizeof(dev_info));
	dev_info.buffer_items_count = buffer_items_count;
	//dev_info.mem_start = mapped_region;
	dev_info.mem_size = 2048;//mem_size;
	dev_info.idle_usec = idle_usec;

	strncpy(dev_info.name, name, HPT_NAMESIZE - 1);
	dev_info.name[HPT_NAMESIZE - 1] = 0;

	ret = ioctl(hpt_fd, HPT_IOCTL_CREATE, &dev_info);
	if (ret < 0) {
		goto error;
	}

	/*
	void *mapped_region = mmap(NULL, 2 * HPT_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, hpt_fd, 0);
	if (mapped_region == MAP_FAILED) {
		perror("Failed to mmap buffers");
		return -1;
	}

	in_buffer = mapped_region;
	out_buffer = mapped_region + HPT_BUFFER_SIZE;
*/
	in_buffer = map_buffers(hpt_fd, 0);
	if (!in_buffer) {
		perror("Failed map_buffers");
		close(hpt_fd);
		return NULL;
	}
	/*
	void *buffers[HPT_BUFFER_COUNT];
    for (int i = 0; i < 1; i++) {
        buffers[i] = map_buffers(hpt_fd, i);
        if (!buffers[i]) {
            close(hpt_fd);
            return -1;
        }

        printf("Buffer %d mapped: encrypted=%p decrypted=%p\n",
               i, buffers[i], buffers[i] + HPT_BUFFER_SIZE);
    }
*/


	hpt = malloc(sizeof(struct hpt));

	if (!hpt) {
		goto error;
	}
/*
	hpt->tx_ring = (struct hpt_ring_buffer *)mapped_region;
	hpt->rx_ring = hpt->tx_ring + 1;
	hpt->tx_start =
		hpt_rb_tx_start(hpt->tx_ring, dev_info.buffer_items_count);
	hpt->rx_start =
		hpt_rb_rx_start(hpt->tx_ring, dev_info.buffer_items_count);
	hpt->rb_size = buffer_items_count;
*/
	hpt->read_cb = read_cb;
	hpt->read_hdl = handle;
	//hpt->ring_memory = buffers;
	hpt->ring_memory_size = mem_size;
	//hpt->kthread_needs_wake = wake_flag;

	printf("HPT: Ready\n");

	return hpt;

error:
/*
	if (mapped_region) {
		munmap(mapped_region, 2 * HPT_BUFFER_SIZE);
	}
*/
	if (hpt) {
		free(hpt);
	}

	return NULL;
}

void hpt_close(struct hpt *hpt_dev)
{
	if (hpt_fd < 0) {
		return;
	}

	//ioctl(hpt_fd, HPT_IOCTL_DESTROY, NULL);

	close(hpt_fd);
	hpt_fd = -1;

	if (hpt_dev) {
		if (in_buffer) {
			munmap(in_buffer, HPT_BUFFER_SIZE);
		}
		free(hpt_dev);
	}
}

void hpt_drain(struct hpt *state)
{
	printf("start hpt_drain\n");
	size_t num = hpt_rb_count(state->tx_ring, state->rb_size);

	for (size_t j = 0; j < num; j++) {
		struct hpt_ring_buffer_element *elem = hpt_rb_rx(
			state->tx_ring, state->rb_size, state->tx_start);

		if (!elem) {
			break;
		}

		state->read_cb(state->read_hdl, elem->data, elem->len);

		hpt_rb_inc_read(state->tx_ring, state->rb_size,
				state->tx_start);
	}
}

void hpt_write(struct hpt *state, uint8_t *ip_pkt, size_t len)
{
	printf("start hpt_write\n");
	memcpy(in_buffer, ip_pkt, len);
	ioctl(hpt_fd, HPT_IOCTL_NOTIFY, NULL);

	//hpt_rb_tx(state->rx_ring, state->rb_size, state->rx_start, ip_pkt, len);
	/*if (ACQUIRE(state->kthread_needs_wake)) {
		printf("ioctl HPT_IOCTL_NOTIFY\n");
		ioctl(hpt_fd, HPT_IOCTL_NOTIFY, NULL);
	}*/
}
