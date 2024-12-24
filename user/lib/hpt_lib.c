#define _POSIX_C_SOURCE 199309L // Enable CLOCK_MONOTONIC and other POSIX features

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include "hpt_lib.h"
#include <time.h>

uint8_t buff_ind;

static inline double get_time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
}

hpt_handle_t *hpt_open(void)
{
    int ret;
    hpt_handle_t *handle = malloc(sizeof(hpt_handle_t));
    if (!handle)
    {
        return NULL;
    }

    handle->fd = open("/dev/hpt", O_RDWR);
    if (handle->fd < 0)
    {
        printf("error open /dev/hpt\n");
        free(handle);
        return NULL;
    }
    printf("open /dev/hpt\n");

    ret = ioctl(handle->fd, HPT_IOCTL_CREATE, NULL);
	if (ret < 0) {
		return NULL;
	}


    // Map the DMA buffer to user space
    handle->mapped_buffer = mmap(NULL,
                                 HPT_ALLOC_SIZE * 2,
                                 PROT_READ | PROT_WRITE,
                                 MAP_SHARED,
                                 handle->fd,
                                 0);


    if (handle->mapped_buffer == MAP_FAILED)
    {
        printf("mmap failed\n");
        close(handle->fd);
        free(handle);
        return NULL;
    }

    printf("Mapped buffer: %p\n", handle->mapped_buffer);

    // Setup ring buffer control structure
    handle->ring_tx = (struct ring_buffer *)handle->mapped_buffer;
    handle->ring_rx = (struct ring_buffer *)handle->mapped_buffer + (HPT_ALLOC_SIZE / sizeof(struct ring_buffer));
    printf("ring_tx: %p, ring_rx %p\n", handle->ring_tx, handle->ring_rx);

    return handle;
}

int hpt_close(hpt_handle_t *handle)
{
    if (!handle)
        return -EINVAL;

    munmap(handle->mapped_buffer, HPT_ALLOC_SIZE * 2);
    close(handle->fd);
    free(handle);
    printf("hpt close\n");

    return 0;
}

void hpt_send(hpt_handle_t *handle)
{
    struct timespec start, end;
    uint32_t i = 1;

	clock_gettime(CLOCK_MONOTONIC, &start); // Start timing
	while(i > 0)
	{
		ioctl(handle->fd, HPT_IOCTL_NOTIFY, NULL);
		i--;
	}
	//ioctl(handle->fd, HPT_IOCTL_NOTIFY, NULL);
	clock_gettime(CLOCK_MONOTONIC, &end);   // End timing

    printf("Time taken to write to buffer: %.2f ns\n", get_time_diff(start, end));

    printf("wIndx %u, rIndx %u\n", handle->ring_tx->write_index, handle->ring_tx->read_index);
}

ssize_t hpt_read(hpt_handle_t *handle, void *buf, size_t count)
{
    if (!handle || !buf || !count || !handle->ring_rx)
        return -EINVAL;
    
    // Check if buffer is empty
    if (handle->ring_rx->read_index == handle->ring_rx->write_index)
        return -EAGAIN;

    /*printf("data0 %s\n", (char *)handle->mapped_buffer + sizeof(struct ring_buffer) + (0 * HPT_BUFFER_SIZE));
    printf("data1 %s\n", (char *)handle->mapped_buffer + sizeof(struct ring_buffer) + (1 * HPT_BUFFER_SIZE));
    printf("data2 %s\n", (char *)handle->mapped_buffer + sizeof(struct ring_buffer) + (2 * HPT_BUFFER_SIZE));
    printf("data3 %s\n", (char *)handle->mapped_buffer + sizeof(struct ring_buffer) + (3 * HPT_BUFFER_SIZE));*/

    // Calculate buffer offset
    uint8_t *buffer_ptr = (uint8_t *)handle->ring_rx +
                       sizeof(struct ring_buffer) +
                       (handle->ring_rx->read_index * HPT_BUFFER_SIZE);

     printf("ring_rx %p, buffer_ptr %p\n", handle->ring_rx, (uint8_t *)buffer_ptr);

    // Copy data from buffer
    if (count > HPT_BUFFER_SIZE)
        count = HPT_BUFFER_SIZE;

    memcpy(buf, buffer_ptr, count);

    // Update read index
    handle->ring_rx->read_index =
        (handle->ring_rx->read_index + 1) % HPT_NUM_BUFFERS;

    for(int i = 0; i < HPT_NUM_BUFFERS; i++)
    {
        printf("%c", buffer_ptr[i]);
    }

    printf("\nrIndx %u\n", handle->ring_rx->read_index);

    return count;
}

void hpt_write(hpt_handle_t *handle)
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

    unsigned char packet[ip_len];
    memcpy(packet, ip_header, sizeof(ip_header));
    memcpy(packet + sizeof(ip_header), udp_header, sizeof(udp_header));
    memcpy(packet + sizeof(ip_header) + sizeof(udp_header), payload, payload_len);

    uint32_t write_idx = handle->ring_tx->write_index;
    uint32_t next_write = (write_idx + 1) % HPT_NUM_BUFFERS;

    // Check if buffer is full
    if (next_write == handle->ring_tx->read_index)
        return;

    void *buffer_ptr = handle->mapped_buffer +
                       sizeof(struct ring_buffer) +
                       (write_idx * HPT_BUFFER_SIZE);

	//memcpy(in_buffer, packet, sizeof(packet));
    memcpy(buffer_ptr, packet, sizeof(packet));

	printf("Indx %d, data %c, addr=%p\n", buff_ind, ch, buffer_ptr);
	buff_ind++;

    handle->ring_tx->write_index = next_write;
    
    printf("wIndx %u, rIndx %u\n", handle->ring_tx->write_index, handle->ring_tx->read_index);
}