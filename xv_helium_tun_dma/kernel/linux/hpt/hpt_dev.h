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
#define HPT_VERSION "1.8"

#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/ethtool.h>
#include <linux/version.h>
#include <linux/debugfs.h>
#include <linux/cdev.h>

#include <hpt/hpt_common.h>

/**
 * The signature of the TX timeout method has changed since 5.6 but we want to be compatible with 5.x so we use this ifdef to support both
 */
#if KERNEL_VERSION(5, 6, 0) <= LINUX_VERSION_CODE
#define HAVE_TX_TIMEOUT_TXQUEUE
#endif

#define HPT_KTHREAD_RESCHEDULE_INTERVAL 0 /* us */
#define HPT_BUFFER_COUNT 65535
#define HPT_BUFFER_SIZE 4096
#define HPT_NUM_BUFFERS 1024
//#define HPT_ALLOC_SIZE (HPT_BUFFER_SIZE * HPT_NUM_BUFFERS)

struct hpt_net_device_info {
	char name[HPT_NAMESIZE];
	size_t ring_buffer_items;
};

typedef struct hpt_data_info {
    int in_use;
	int ready_flag_rx;
	int ready_flag_tx;
	int size;
}hpt_data_info_t;

struct hpt_dma_buffer {
	void *data_combined;              
	dma_addr_t dma_handle;
};

struct hpt_dev {
	char name[HPT_NAMESIZE];
	size_t ring_buffer_items;
    struct class *class;
    struct device *device;
    struct cdev cdev;
    dev_t devt;
    struct hpt_dma_buffer buffers[HPT_BUFFER_COUNT]; // Buffer pool
    struct platform_device *pdev;
    struct mutex lock;
	struct task_struct *pthread;
	struct net_device *net_dev;
	spinlock_t buffer_lock;
	int event_flag;
	wait_queue_head_t read_wait_queue;
	wait_queue_head_t tx_busy;
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