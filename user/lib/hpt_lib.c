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
int fd;

static inline double get_time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
}

int hpt_fd(struct hpt *dev)
{
    return fd;
}

int hpt_init()
{
    fd = open("/dev/hpt", O_RDWR);
    if (fd < 0)
    {
        printf("error open /dev/hpt\n");
        return -1;
    }
    printf("open /dev/hpt\n");

    return 0;
}

void *map_buffers(int fd, int buffer_idx) {
    void *mapped;
	
    size_t page_size = sysconf(_SC_PAGE_SIZE);
 
    mapped = mmap(NULL, HPT_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, buffer_idx * page_size);
    if (mapped == MAP_FAILED) {
        perror("Failed to mmap buffers");
        return NULL;
    }

    return mapped;
}

struct hpt *hpt_alloc(const char name[HPT_NAMESIZE], size_t num_ring_items)
{
    int ret;
    struct hpt *dev = malloc(sizeof(struct hpt));

    if(!dev) 
    {
        printf("Cannot allocate 'struct hpt'\n");
        return NULL;
    }

    if(num_ring_items > HPT_BUFFER_COUNT) 
    {
        printf("Too many elements for buffer'\n");
        return NULL;
    }

    struct hpt_net_device_info net_dev_info;

    memset(&net_dev_info, 0, sizeof(net_dev_info));
	net_dev_info.ring_buffer_items = num_ring_items;

	strncpy(net_dev_info.name, name, HPT_NAMESIZE - 1);
	net_dev_info.name[HPT_NAMESIZE - 1] = 0;

	ret = ioctl(fd, HPT_IOCTL_CREATE, &net_dev_info);
	if (ret < 0) {
		return NULL;
	}

/*
    // Map the DMA buffer to user space
    hpt->mapped_buffer = mmap(NULL,
                                 HPT_ALLOC_SIZE * 2,
                                 PROT_READ | PROT_WRITE,
                                 MAP_SHARED,
                                 fd,
                                 0);


    if (hpt->mapped_buffer == MAP_FAILED)
    {
        printf("mmap failed\n");
        close(fd);
        free(hpt);
        return NULL;
    }
*/
    printf("Mapped buffer\n");

    // Setup ring buffer control structure
    //hpt->ring_tx = (struct ring_buffer *)hpt->mapped_buffer;
    //hpt->ring_rx = (struct ring_buffer *)hpt->mapped_buffer + (HPT_ALLOC_SIZE / sizeof(struct ring_buffer));
    //printf("ring_tx: %p, ring_rx %p\n", hpt->ring_tx, hpt->ring_rx);

    return dev;
}

void hpt_close(struct hpt *dev)
{
    if(!dev) return;
    close(fd);
    free(dev);
    printf("hpt close\n");

    return;
}

void hpt_read(struct hpt *dev, hpt_buffer_t *buf)
{
    if (!dev)
        return;

    size_t start_len = dev->ring_buffer_items >> 1;
    for (int i = start_len; i < dev->ring_buffer_items; i++) {
        buf->base = map_buffers(fd, i);
        if (!buf->base) {
            close(fd);
            free(dev);
            printf("error map buffer\n");
            return;
        }
    }

    for(int i = 0; i < HPT_BUFFER_SIZE; i++)
    {
        printf("%c", buf->base[i]);
    }

	munmap(buf->base, HPT_BUFFER_SIZE);    
}

void message(void *buf)
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

    memcpy(buf, ip_header, sizeof(ip_header));
    memcpy(buf + sizeof(ip_header), udp_header, sizeof(udp_header));
    memcpy(buf + sizeof(ip_header) + sizeof(udp_header), payload, payload_len);

    //buf->capacity = HPT_NUM_BUFFERS;
    //buf->len = HPT_BUFFER_SIZE;
	buff_ind++;
}

void hpt_write(struct hpt *dev, hpt_buffer_t *buf)
{
    if (!dev)
        return;

    size_t end_len = dev->ring_buffer_items >> 1;
    for (int i = 0; i < end_len; i++) {
        dev->mapped_buffer = map_buffers(fd, i);
        if (!dev->mapped_buffer) {
            close(fd);
            free(dev);
            printf("error map buffer\n");
            return;
        }
    }

    struct timespec start, end;
    uint32_t i = 1;

	clock_gettime(CLOCK_MONOTONIC, &start); // Start timing
	while(i > 0)
	{
        message(dev->mapped_buffer);
		i--;
	}
    ioctl(fd, HPT_IOCTL_NOTIFY, NULL);

	//ioctl(fd, HPT_IOCTL_NOTIFY, NULL);
	clock_gettime(CLOCK_MONOTONIC, &end);   // End timing

    printf("Time taken to write to buffer: %.2f ns\n", get_time_diff(start, end));

    munmap(buf->base, HPT_BUFFER_SIZE);    
}