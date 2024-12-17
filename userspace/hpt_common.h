#ifndef _HPT_COMMON_H_
#define _HPT_COMMON_H_

#ifdef __KERNEL__
#include <linux/if.h>
#include <asm/barrier.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#else
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#include <stdint.h>
#endif
#include <stdio.h>
#include <string.h>

/*
 * HPT name is part of memzone name. Must not exceed IFNAMSIZ.
 */
#define HPT_NAMESIZE 32
#define HPT_RB_ELEMENT_SIZE 2048
#define HPT_RB_ELEMENT_USABLE_SPACE (HPT_RB_ELEMENT_SIZE - sizeof(uint16_t))
#define HPT_MTU 1350
#define HPT_MAX_ITEMS 65536

/**
 * Single-Producer Single-Consumer Lockless Ring Buffers.
 * These are all proprietary - need to be checked thoroughly - decided to ditch DPDK's
 *
 * We pass the number of ring buffer items out-of-band since this memory is shared with userspace
 * so userspace could change the limits leading to out-of-bounds reads.
 * Instead, we fix the limit at allocation and allow only the read and write heads to be changed.
 */

struct hpt_ring_buffer {
	uint64_t write;
	uint64_t read;
} __attribute((packed));

struct hpt_ring_buffer_element {
	uint16_t len;
	uint8_t data[HPT_RB_ELEMENT_USABLE_SPACE];
} __attribute((packed));

/**
 * Read & Write for lockless data structures.
 * Acquire makes sure everything is coherent with the last store.
 * Store also stops compiler optimizing by using partial writes (stuff like *u32 -> (*u16 + *(u16 + 1)).
 */
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

/**
 * This method returns the number of bytes in a single ring. It is used to calculate the offset from the first to the second ring in memory.
 */
static inline size_t hpt_rb_ring_buffer_stride(size_t ring_buffer_items)
{
	return HPT_RB_ELEMENT_SIZE * ring_buffer_items;
}

/**
 * Ring buffers are laid out in memory as (meta struct for tx)(meta struct for rx)(data for tx)(data for rx).
 * the metastructures are 128-bit aligned structs and HPT_RB_ELEMENT_SIZE is always a power of two so structure offsets will always be aligned.
 * These two methods calculate the data portion start offsets from the tx_ring entry.
 */
static inline uint8_t *hpt_rb_tx_start(
	struct hpt_ring_buffer *ring,
	size_t _ring_buffer_items /* Leave it here just to keep the API consistent, it will get compiled out */)
{
	return (uint8_t *)(ring + 2);
}

static inline uint8_t *hpt_rb_rx_start(struct hpt_ring_buffer *ring,
				       size_t ring_buffer_items)
{
	return hpt_rb_tx_start(ring, ring_buffer_items) +
	       hpt_rb_ring_buffer_stride(ring_buffer_items);
}

/**
 * How many tx elements are waiting unread
 */
static inline uint64_t hpt_rb_count(struct hpt_ring_buffer *ring,
				    size_t ring_buffer_items)
{
	uint64_t unread_items = ACQUIRE(&ring->write) - ACQUIRE(&ring->read);
	if (unlikely(unread_items > ring_buffer_items)) {
		return ring_buffer_items;
	}
	return unread_items;
}

/**
 * How many more elements can we write without running out of space
 */
static inline uint64_t hpt_rb_free(struct hpt_ring_buffer *ring,
				   size_t ring_buffer_items)
{
	return ring_buffer_items - hpt_rb_count(ring, ring_buffer_items);
}

/**
 * Calculate the ring element we need.
 * Note: We could remove the expensive division but we are not CPU bottlenecked. Only optimize it out if we really need to since needing to account for write < read increases edge cases a lot.
 */
static inline struct hpt_ring_buffer_element *
hpt_rb_element(uint8_t *start, size_t slot, size_t ring_buffer_items)
{
	/* Mod the ring slot by the size of the rb in items */
	slot = slot % ring_buffer_items;

	/* Find the start of the ring in memory */
	start += (HPT_RB_ELEMENT_SIZE * slot);

	/* Return it as a ring buffer element */
	return (struct hpt_ring_buffer_element *)start;
}

/**
 * 'Transmit' a packet. Copies it onto a given ring and increments the write head.
 */
static inline int hpt_rb_tx(struct hpt_ring_buffer *ring,
			    size_t ring_buffer_items, uint8_t *tx_start,
			    uint8_t *data, size_t len)
{
	struct hpt_ring_buffer_element *elem;

	if (unlikely(!hpt_rb_free(ring, ring_buffer_items))) {
		printf("hpt_rb_free(ring, ring_buffer_items)\n");
		return -1;
	}

	/* Check if the length of skb is less than mbuf size */
	if (unlikely(len > HPT_RB_ELEMENT_USABLE_SPACE)) {
		printf("len > HPT_RB_ELEMENT_USABLE_SPACE\n");
		return -1;
	}

	/* Now we know we are in bounds, select the ring slot */
	elem = hpt_rb_element(tx_start, ACQUIRE(&ring->write), ring_buffer_items);

	/* Copy in the element */
	elem->len = len;
	memcpy(elem->data, data, len);

	/* Increment the write head */
	STORE(&ring->write, ACQUIRE(&ring->write) + 1);

	return 0;
}

/**
 * 'Receive' a packet, returning a pointer to a struct.
 * This does not increment the read head - this memory will not be reused by the ring until hpt_rb_inc_read is called.
 * This is to avoid a memcpy - you can process this memory directly and then inc the head.
 */
static inline struct hpt_ring_buffer_element *
hpt_rb_rx(struct hpt_ring_buffer *ring, size_t ring_buffer_items,
	  uint8_t *dstart)
{
	struct hpt_ring_buffer_element *elem;

	/* Check that the ring buffer has some items */
	if (unlikely(!hpt_rb_count(ring, ring_buffer_items))) {
		return NULL;
	}

	/* Now we know we are in bounds, select the ring slot */
	elem = hpt_rb_element(dstart, ACQUIRE(&ring->read), ring_buffer_items);

	/* Check for length corruption on the ring buffer */
	if (unlikely(elem->len > HPT_RB_ELEMENT_USABLE_SPACE)) {
		return NULL;
	}

	return elem;
}

/**
 * Remove the current packet from the ring buffer and clear its memory.  The
 * current packet is passed in as pkt.
 */
static inline void hpt_rm_cur_ring_pkt(struct hpt_ring_buffer *ring,
				       struct hpt_ring_buffer_element *pkt)
{
	memset(pkt, 0, sizeof(*pkt));
	STORE(&ring->read, ACQUIRE(&ring->read) + 1);
}

/**
 * Increment the read head.
 * The memory associated with the current element may be modified after.
 */
static inline void hpt_rb_inc_read(struct hpt_ring_buffer *ring,
				   size_t ring_buffer_items, uint8_t *dstart)
{
	struct hpt_ring_buffer_element *elem;

	/* Don't increment the read head if read == write */
	if (unlikely(!hpt_rb_count(ring, ring_buffer_items))) {
		return;
	}

	/* Zero the RB in memory before we increment the read head */
	elem = hpt_rb_rx(ring, ring_buffer_items, dstart);

	/* Check that we can fetch the RB element (it should be impossible for this to fail unless there are concurrent readers)*/
	if (!elem) {
		return;
	}

	memset(elem, 0, sizeof(struct hpt_ring_buffer_element));

	/* Increment the read head */
	STORE(&ring->read, ACQUIRE(&ring->read) + 1);
}

/*
 * Struct used to create a HPT device. Passed to the kernel in IOCTL call
 */

struct hpt_device_info {
	char name[HPT_NAMESIZE]; /**< Network device name for HPT */

	size_t ring_buffer_items;

	void *mem_start;
	size_t mem_size;
	size_t idle_usec;
};

#define HPT_DEVICE "hpt"

#define HPT_IOCTL_CREATE _IOWR(0x92, 2, struct hpt_device_info)
#define HPT_IOCTL_NOTIFY _IO(0x92, 3)

#endif
