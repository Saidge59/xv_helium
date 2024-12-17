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

/**
 * The hpt_do_packet callback is called during hpt_drain
 * after each packet is read with the packet data and size.
 */
typedef void (*hpt_do_pkt)(void *handle, uint8_t *pkt_data, size_t pkt_size);

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
 * Write a packet to the HPT.
 */
void hpt_write(struct hpt *state, uint8_t *ip_pkt, size_t len);

#endif
