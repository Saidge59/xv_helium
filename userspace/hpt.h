#ifndef _HPT_H_
#define _HPT_H_

/*
 * This is the central header for the userspace component of the high performance tun device.
 *
 * This code is inspired by work from DPDK, published by Intel (the HPT driver)
 * Copyright(c) 2010-2014 Intel Corporation. 
 *
 * That code was inspired from the book "Linux Device Drivers" by
 * Alessandro Rubini and Jonathan Corbet, published by O'Reilly & Associates
 */

#include "hpt_common.h"

#define HPT_BUFFER_COUNT 1024
#define HPT_BUFFER_SIZE 2048

struct hpt;

/**
 * The hpt_do_packet callback is called during hpt_drain
 * after each packet is read with the packet data and size.
 */
typedef void (*hpt_do_pkt)(void *handle, uint8_t *pkt_data, size_t pkt_size);

/**
 * Initialize the high performance tun (open a handle to /dev/hpt) but do not create a tun device.
 * Permissions for creating the tun device will be checked here.
 */
int hpt_init();

/**
 * Close the HPT. This will close the file descriptor to /dev/hpt and shut down the tun device if it exists.
 * If no device has been initialized pass NULL, otherwise pass the initialized device.
 */
void hpt_close(struct hpt *hpt_dev);

/**
 * Allocate a HPT instance. This must be called after a successful call to hpt_init.
 */
struct hpt *hpt_alloc(const char name[HPT_NAMESIZE], size_t num_ring_items,
		      hpt_do_pkt read_cb, void *read_handle, size_t idle_usec);

/**
 * This file descriptor will raise POLL_IN whenever there is data to drain from the ring buffer. 
 */
int hpt_wake_fd();

/**
 * This method will drain the items on the ring at the time that it is called.
 * It does not loop forever - if items are added during drain they will be ignored.
 */
void hpt_drain(struct hpt *state);

/**
 * New data of payload.
 */
void hpt_payload();

/**
 * Write a packet to the HPT.
 */
void hpt_write();

#endif
