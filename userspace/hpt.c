#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <sys/mman.h>
#include <time.h> // For performance timing

#include "hpt.h"

static volatile int hpt_fd = -1;

// Utility to measure elapsed time
static double get_time_elapsed(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->tv_nsec) / 1e9;
}

int hpt_wake_fd()
{
	return hpt_fd;
}

int hpt_init()
{
	struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

	if (hpt_fd < 0) {
		hpt_fd = open("/dev/" HPT_DEVICE, O_RDWR);
		if (hpt_fd < 0) {
			printf("HPT: Err: %i\n", hpt_fd);
			return -1;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
    printf("HPT initialization took %.9f seconds\n", get_time_elapsed(&start, &end));
    return 0;
}

struct hpt *hpt_alloc(const char name[HPT_NAMESIZE], size_t ring_buffer_items,
		      hpt_do_pkt read_cb, void *handle, size_t idle_usec)
{
	struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

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

	//uint8_t *ring_memory = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	/** The kernel allocates the rings and we mmap the allocated memory into userspace **/
	uint8_t *ring_memory = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, hpt_fd, 0);

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

	return NULL;
	//=====================================================================

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

    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("HPT allocation took %.9f seconds\n", get_time_elapsed(&start, &end));

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
	struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

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
	
	clock_gettime(CLOCK_MONOTONIC, &end);
    printf("HPT close took %.9f seconds\n", get_time_elapsed(&start, &end));
}

void hpt_drain(struct hpt *state)
{
	printf("start hpt_drain\n");
	struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);


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

    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("HPT drain processed %zu packets in %.9f seconds\n", num, get_time_elapsed(&start, &end));
}

void hpt_write(struct hpt *state, uint8_t *ip_pkt, size_t len)
{
	printf("start hpt_write\n");
	struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    //pt_rb_tx(state->rx_ring, state->rb_size, state->rx_start, ip_pkt, len);
	uint8_t i = 10;
	while(i > 0)
	{
		ioctl(hpt_fd, HPT_IOCTL_NOTIFY, NULL);
		i--;
	}


/*    
	if (ACQUIRE(state->kthread_needs_wake)) {
        ioctl(hpt_fd, HPT_IOCTL_NOTIFY, NULL);
    }
*/
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("HPT write took %.9f seconds\n", get_time_elapsed(&start, &end));
}
