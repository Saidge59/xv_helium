#define _POSIX_C_SOURCE 199309L // Enable CLOCK_MONOTONIC and other POSIX features

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <sys/mman.h>
#include <time.h>
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
uint8_t buff_ind;
int message(uint8_t *data);

static inline double get_time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
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

struct hpt *hpt_alloc(const char name[HPT_NAMESIZE], size_t ring_buffer_items,
		      hpt_do_pkt read_cb, void *handle, size_t idle_usec)
{
	int ret;
	struct hpt_device_info dev_info;
	struct hpt *hpt = NULL;

	if (!name || !ring_buffer_items) {
		return NULL;
	}

	/* Check if HPT subsystem has been initialized */
	if (hpt_fd < 0) {
		printf("HPT: is not initialized. try again\n");
		return NULL;
	}

	printf("HPT: Mapping in the memory\n");

	if (ring_buffer_items > HPT_MAX_ITEMS) {
		printf("HPT: hpt rings only support up to %u ring buffer items\n",
		       HPT_MAX_ITEMS);
		return NULL;
	}

	size_t mem_size = (2 * sizeof(struct hpt_ring_buffer)) +
			  (2 * hpt_rb_ring_buffer_stride(ring_buffer_items)) + sizeof(uint8_t);

	/** The kernel allocates the rings and we mmap the allocated memory into userspace **/
	uint8_t *ring_memory = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	uint8_t *wake_flag = ring_memory + mem_size - sizeof(uint8_t);

	if (ring_memory == MAP_FAILED) {
		printf("Could not map the kernel memory. Fatal error.\n");
		return NULL;
	}

	printf("HPT: Mapped memory into userspace at %p\n", ring_memory);

	memset(&dev_info, 0, sizeof(dev_info));
	dev_info.ring_buffer_items = ring_buffer_items;
	dev_info.mem_start = ring_memory;
	dev_info.mem_size = mem_size;
	dev_info.idle_usec = idle_usec;

	strncpy(dev_info.name, name, HPT_NAMESIZE - 1);
	dev_info.name[HPT_NAMESIZE - 1] = 0;

	ret = ioctl(hpt_fd, HPT_IOCTL_CREATE, &dev_info);

	if (ret < 0) {
		goto error;
	}

	hpt = malloc(sizeof(struct hpt));

	if (!hpt) {
		goto error;
	}

	hpt->tx_ring = (struct hpt_ring_buffer *)ring_memory;
	hpt->rx_ring = hpt->tx_ring + 1;
	hpt->tx_start =
		hpt_rb_tx_start(hpt->tx_ring, dev_info.ring_buffer_items);
	hpt->rx_start =
		hpt_rb_rx_start(hpt->tx_ring, dev_info.ring_buffer_items);
	hpt->rb_size = ring_buffer_items;

	hpt->read_cb = read_cb;
	hpt->read_hdl = handle;
	hpt->ring_memory = ring_memory;
	hpt->ring_memory_size = mem_size;
	hpt->kthread_needs_wake = wake_flag;

	printf("HPT: Ready\n");

	return hpt;

error:

	if (ring_memory) {
		munmap(ring_memory, mem_size);
	}

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

	close(hpt_fd);
	hpt_fd = -1;

	if (hpt_dev) {
		if (hpt_dev->ring_memory) {
			munmap(hpt_dev->ring_memory, hpt_dev->ring_memory_size);
		}
		free(hpt_dev);
	}
}

void hpt_drain(struct hpt *state)
{
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
	printf("hpt_write\n");
			
	struct timespec start, end;
	uint32_t size = 1000;
	uint32_t i = 0;

	clock_gettime(CLOCK_MONOTONIC, &start); // Start timing

	while(i++ < size)
	{
		//message(ip_pkt);
		hpt_rb_tx(state->rx_ring, state->rb_size, state->rx_start, ip_pkt, len);
		ioctl(hpt_fd, HPT_IOCTL_NOTIFY, NULL);
	}
	clock_gettime(CLOCK_MONOTONIC, &end);   // End timing

   	uint32_t time = (uint32_t)get_time_diff(start, end);
    printf("Time of all buffers %u ns, one buffer %u ns\n", time, time/size);
}


int message(uint8_t *data)
{
    unsigned char ip_header[] = {
        0x45, 0x00, 0x00, 0x00, 
        0x1C, 0x46, 0x40, 0x00, 
        0x40, 0x11, 0x00, 0x00, 
        0xC0, 0xA8, 0x1F, 0xC8, // 192.168.31.200
        0xC0, 0xA8, 0x1F, 0xC9  // 192.168.31.201
    };

    unsigned char udp_header[] = {
        0x48, 0x1D, 0x6C, 0x5C,
        0x00, 0x00, 0x00, 0x00
    };

    const size_t len = 1024;
    char payload[len];
	char ch = 'a' + buff_ind;
    memset(payload, ch, len);
    size_t payload_len = strlen(payload);

    size_t udp_len = sizeof(udp_header) + payload_len;
    size_t ip_len = sizeof(ip_header) + udp_len;

    ip_header[2] = (ip_len >> 8) & 0xFF;
    ip_header[3] = ip_len & 0xFF;

    udp_header[4] = (udp_len >> 8) & 0xFF;
    udp_header[5] = udp_len & 0xFF;

    size_t size = sizeof(ip_header) + sizeof(udp_header) + payload_len;

    memcpy(data, ip_header, sizeof(ip_header));
    memcpy(data + sizeof(ip_header), udp_header, sizeof(udp_header));
    memcpy(data + sizeof(ip_header) + sizeof(udp_header), payload, payload_len);

	buff_ind++;
    return 0;
}