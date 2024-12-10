#ifndef _HPT_DEV_H_
#define _HPT_DEV_H_

/*
 * This is the central header for the kernel component of the high performance tun device.
 *
 * This code is inspired by work from DPDK, published by Intel (the HPT driver)
 * Copyright(c) 2010-2014 Intel Corporation. 
 *
 * That code was inspired from the book "Linux Device Drivers" by
 * Alessandro Rubini and Jonathan Corbet, published by O'Reilly & Associates
 */

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define HPT_VERSION "1.7"

#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/ethtool.h>
#include <linux/version.h>
#include <linux/debugfs.h>

#include <hpt/hpt_common.h>

/**
 * The signature of the TX timeout method has changed since 5.6 but we want to be compatible with 5.x so we use this ifdef to support both
 */
#if KERNEL_VERSION(5, 6, 0) <= LINUX_VERSION_CODE
#define HAVE_TX_TIMEOUT_TXQUEUE
#endif

#define HPT_KTHREAD_RESCHEDULE_INTERVAL 0 /* us */

/**
 * A structure describing the private information for a hpt device.
 */
struct hpt_dev {
	/* Network device name */
	char name[HPT_NAMESIZE];

	/* Kernel thread that handles userspace -> kernel path (rx) */
	struct task_struct *pthread;

	/* the hpt network device */
	struct net_device *net_dev;

	/* This keeps track of whether we should EPOLLIN currently or not */
	wait_queue_head_t tx_busy;

	/* Our structure will contain two ring buffers mmapped contiguously
	 * in memory each with head struct in front.
	 * We keep track of ring_buffer_items separately (fixed during the
	 * ioctl) to avoid userspace being able to change
	 * the rb length to read out of bounds memory
	 */
	size_t ring_buffer_items;

	/* Pointers to the tx and tx metdata and element starts in memory. */
	struct hpt_ring_buffer *tx_ring;
	uint8_t *tx_start;

	struct hpt_ring_buffer *rx_ring;
	uint8_t *rx_start;

	/* Pointer to the memory as it is mapped in. */
	void *ring_memory;
	size_t num_ring_memory;

	/* The physical pages that we mapped */
	struct page **mapped_pages;
	unsigned long num_mapped_pages;

	struct dentry	*hd_dbgfs_tun_dir;

	uint64_t	hd_rx_empty;
	uint64_t	hd_rx_len_zero;
	uint64_t	hd_rx_len_over;
	uint64_t	hd_rx_called;
	uint64_t	hd_rx_non_ip;
	uint64_t	hd_rx_skb_alloc_err;
	uint64_t	hd_rx_netif_drop;

	uint64_t	hd_tx_errs;
	uint64_t	hd_tx_len_zero;
	uint64_t	hd_tx_len_over;

	/* Read thread wait queue */
	wait_queue_head_t read_wait_queue;

	uint8_t *kthread_needs_wake;
	size_t kthread_idle_jiffies;
};

struct hpt_mod_info {
	struct dentry *hmi_dbgfs_root;
};

/* File names exported in debugfs to show the internal ring processing
 * information.
 */
#define	HPT_DBGFS_TX_RING_READ		"tx_ring_read_ptr"
#define	HPT_DBGFS_TX_RING_WRITE		"tx_ring_write_ptr"
#define	HPT_DBGFS_TX_RING_ERRS		"tx_ring_errs"
#define	HPT_DBGFS_TX_RING_LEN_ZERO	"tx_ring_zero_len_errs"
#define	HPT_DBGFS_TX_RING_LEN_OVER	"tx_ring_too_big_errs"

#define	HPT_DBGFS_RX_RING_READ		"rx_ring_read_ptr"
#define	HPT_DBGFS_RX_RING_WRITE		"rx_ring_write_ptr"
#define	HPT_DBGFS_RX_RING_EMPTY		"rx_ring_empty"
#define	HPT_DBGFS_RX_RING_LEN_ZERO	"rx_ring_zero_len_errs"
#define	HPT_DBGFS_RX_RING_LEN_OVER	"rx_ring_too_big_errs"
#define	HPT_DBGFS_RX_RING_PROC		"rx_ring_proc"
#define	HPT_DBGFS_RX_RING_NON_IP	"rx_ring_non_ip"
#define	HPT_DBGFS_RX_RING_MEM_ERR	"rx_ring_memory_err"
#define	HPT_DBGFS_RX_NETIF_DROP 	"rx_netif_drop"

/**
 * This function will drain any packets that have been sent to us from userspace
 * and send them to the kernel for processing. It's called by the rx kernel
 * thread created in the core.
 */
size_t hpt_net_rx(struct hpt_dev *hpt);

/**
 * Initialize the network device for the tun, the structure responsible for actually
 * transferring packets (the character device is just used to communicate with userspace).
 */
void hpt_net_init(struct net_device *dev);

#endif
