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
    return(end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
}

int hpt_fd(struct hpt *dev)
{
    return fd;
}

int hpt_init()
{
    fd = open("/dev/hpt", O_RDWR);
    if(fd < 0)
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
    if(mapped == MAP_FAILED) {
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

    dev->ring_buffer_items = num_ring_items;


    for(int i = 0; i < num_ring_items; i++)
    {
        dev->buffers[i].data_combined = map_buffers(fd, i);
        if (!dev->buffers[i].data_combined) {
            close(fd);
            free(dev);
            printf("error map buffer\n");
            return NULL;
        }
        hpt_data_info_t *data_info = (hpt_data_info_t *)dev->buffers[i].data_combined;
        data_info->ready_flag_rx = 0;
    }

    printf("Allocate buffer success!\n");

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
    if(!dev) return;

	size_t start = dev->ring_buffer_items >> 1;
    size_t end = dev->ring_buffer_items;

    for(int i = start; i < end; i++)
    {
        struct hpt_dma_buffer *buffer = &dev->buffers[i];
        hpt_data_info_t *data_info = (hpt_data_info_t *)buffer->data_combined;
        uint8_t *data = (uint8_t *)data_info + sizeof(hpt_data_info_t);

        if(!data_info->in_use) continue;

        if(data_info->size > (HPT_BUFFER_SIZE - sizeof(hpt_data_info_t)))
        {
            printf("Too big a packet for write\n");
            data_info->in_use = 0;
            continue;
        }

        memcpy(buf->base, data, data_info->size);
        data_info->in_use = 0;

        for(int i = 0; i < HPT_BUFFER_SIZE; i++)
        {
            printf("%c", ((char *)buf->base)[i]);
        }
        printf("\n=========================\n");
    }
}

void hpt_write(struct hpt *dev, hpt_buffer_t *buf)
{
    if(!dev) return;

    size_t start = 0;
    size_t end = dev->ring_buffer_items >> 1;

    for(int i = start; i < end; i++)
    {
        struct hpt_dma_buffer *buffer = &dev->buffers[i];
        hpt_data_info_t *data_info = (hpt_data_info_t *)buffer->data_combined;

        if(data_info->in_use) continue;

        if(check_time(data_info)) return;
        data_info->in_use = 1;
        data_info->ready_flag_rx = 1;

        break;
    }
}

int message(hpt_data_info_t *data_info)
{
    uint8_t *data = (uint8_t *)data_info + sizeof(hpt_data_info_t);

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
    if(size > (HPT_BUFFER_SIZE - sizeof(hpt_data_info_t)))
    {
        printf("Too big a packet for write\n");
        data_info->in_use = 0;
        return -1;
    }

    memcpy(data, ip_header, sizeof(ip_header));
    memcpy(data + sizeof(ip_header), udp_header, sizeof(udp_header));
    memcpy(data + sizeof(ip_header) + sizeof(udp_header), payload, payload_len);

    data_info->size = sizeof(ip_header) + sizeof(udp_header) + payload_len;
	buff_ind++;
    return 0;
}

int check_time(hpt_data_info_t *data_info)
{
    struct timespec start, end;
    uint32_t size = 1000;
    uint32_t i = 0;

	clock_gettime(CLOCK_MONOTONIC, &start);
    
	while(i++ < size)
	{
        if(message(data_info)) return -1;
        //ioctl(fd, HPT_IOCTL_NOTIFY, NULL);
	}

	clock_gettime(CLOCK_MONOTONIC, &end);

    uint32_t time = (uint32_t)get_time_diff(start, end);
    printf("Time of all buffers %u ns, one buffer %u ns\n", time, time/size);

    return 0;
}