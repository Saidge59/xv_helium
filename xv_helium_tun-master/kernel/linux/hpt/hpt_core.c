#include <hpt/hpt_common.h>
#include "hpt_dev.h"

MODULE_VERSION(HPT_VERSION);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Blake Loring");
MODULE_DESCRIPTION("High Performance TUN device");

struct hpt_mod_info hmi;

static int hpt_kernel_thread(void *param)
{
	pr_info("Kernel RX thread started!\n");
	struct hpt_dev *dev = param;
	size_t timeout = jiffies + dev->kthread_idle_jiffies;
	const long schedule_timout = usecs_to_jiffies(HPT_KTHREAD_RESCHEDULE_INTERVAL);

	while (true) {

		// Wait for some idle time before commiting to sleeping
		if (time_after_eq(jiffies, timeout)) {
			STORE(dev->kthread_needs_wake, 1);
			// Go to sleep if there aren't any packets
			wait_event_interruptible(dev->read_wait_queue, hpt_rb_count(dev->rx_ring, dev->ring_buffer_items) || kthread_should_stop());
			STORE(dev->kthread_needs_wake, 0);
		} else {
			/**
			 * This short sleep will release the cpu to allow for other tasks to be run on it
			 * this is important or ksoftirqd will never process the packet backlogs
			 */
			schedule_timeout_interruptible(schedule_timout);
		}

		// If we got killed, abort the loop
		if(kthread_should_stop()) {
			pr_info("Kernel RX thread killed exiting RX loop\n");
			break;
		}

		// Consume any packet and if data was consumed, reset our idle timer
		if (hpt_net_rx(dev) > 0) {
			timeout = jiffies + dev->kthread_idle_jiffies;
		}
	}

	pr_info("Kernel RX thread stopped!\n");
	return 0;
}

static inline bool hpt_capable(void)
{
	return capable(CAP_NET_ADMIN);
}

static int hpt_open(struct inode *inode, struct file *file)
{
	int ret;

	pr_info("Security check\n");

	ret = security_tun_dev_create();

	if (ret < 0) {
		return ret;
	}

	if (!hpt_capable()) {
		return -EINVAL;
	}

	file->private_data = NULL;
	pr_info("/dev/hpt opened\n");
	return 0;
}

static void hpt_unmap_pages(struct hpt_dev *hpt)
{
	if (hpt->ring_memory) {
		pr_info("Freeing ring memory\n");

		// First unmap the memory from the virtual table
		vm_unmap_ram(hpt->ring_memory, hpt->num_mapped_pages);

		pr_info("Unpinning user pages");

		// Then unpin all the pages we made sure don't get swapped
		unpin_user_pages_dirty_lock(hpt->mapped_pages, hpt->num_mapped_pages, true);

		pr_info("Freeing page list");

		// Next free the kernel mem we used to store the page list
		vfree(hpt->mapped_pages);

		pr_info("Freed mapped pages");

		// Now null everything
		hpt->mapped_pages = NULL;
		hpt->num_mapped_pages = 0;

		hpt->tx_start = NULL;
		hpt->rx_start = NULL;
		hpt->tx_ring = NULL;
		hpt->rx_ring = NULL;

		hpt->ring_memory = NULL;
		hpt->num_ring_memory = 0;

		pr_info("Free'd ring memory\n");
	}
}

static int hpt_release(struct inode *inode, struct file *file)
{
	int retval = -EINVAL;
	struct hpt_dev *hpt = NULL;

	rtnl_lock();

	hpt = file->private_data;

	if (!hpt) {
		pr_err("cannot free unallocated device");
		retval = -EINVAL;
		goto exit;
	}

	pr_info("Beginning HPT release\n");

	if (hpt->hd_dbgfs_tun_dir)
		debugfs_remove_recursive(hpt->hd_dbgfs_tun_dir);

	/* Stop kernel thread for multiple mode */
	if (hpt->pthread != NULL) {
		kthread_stop(hpt->pthread);
		hpt->pthread = NULL;
	}

	pr_info("Stopped pthread\n");

	/* We cannot free the net-dev yet but it should be unregistered
	 * otherwise tx could race the unmap causing memory misuse
	 */
	unregister_netdevice(hpt->net_dev);

	hpt_unmap_pages(hpt);

	// TODO: Figure this out put_net(net);
	pr_info("/dev/hpt closed\n");

	retval = 0;

exit:

	rtnl_unlock();
	return 0;
}

static int hpt_run_thread(struct hpt_dev *hpt)
{
	pr_info("beginning kernel thread\n");

	/**
	 * Create a new kernel thread to drain userspace packets and send them to the kernel 
	 */
	hpt->pthread = kthread_create(hpt_kernel_thread, (void *)hpt, "%s",
				      hpt->name);

	if (IS_ERR(hpt->pthread)) {
		return -ECANCELED;
	}

	pr_info("Kernel RX thread created\n");

	wake_up_process(hpt->pthread);

	return 0;
}

static unsigned int hpt_poll(struct file *file,
			     struct poll_table_struct *poll_table)
{
	struct hpt_dev *dev = file->private_data;

	unsigned int mask = 0;

	if (dev) {
		poll_wait(file, &dev->tx_busy, poll_table);
		if (hpt_rb_count(dev->tx_ring, dev->ring_buffer_items)) {
			mask |= POLLIN | POLLRDNORM; /* readable */
		}
	}

	return mask;
}

static int hpt_map_in_pages(struct hpt_dev *hpt, struct hpt_device_info *info)
{
	struct page **pages = NULL;

	int retval;
	int nid;
	int pinned_pages = 0;
	unsigned long npages;
	unsigned long buffer_start =
		(unsigned long)info->mem_start; // Address from user-space map.
	unsigned long mem_size =
		hpt->num_ring_memory; // Memory size that we derive from ring_buffer_items. This has already been checked such that mem_size < info.mem_size, so the userspace program has left enough space for us.

	if (!mem_size) {
		pr_err("cannot allocate a zero-sized ring");
		retval = -1;
		goto cleanup;
	}

	/*
   * Check that the addition of the memory we want to allocate to the start of the buffer will not overflow the address space
   * As an unsigned long this overflow is well defined
   */
	if (buffer_start + mem_size < buffer_start) {
		pr_err("buffer start too close to end of memory");
		retval = -1;
		goto cleanup;
	}

	npages = 1 + ((mem_size - 1) / PAGE_SIZE);

	if (npages < 1) {
		pr_err("not enough pages");
		retval = -1;
		goto cleanup;
	}

	pages = vmalloc(npages * sizeof(struct page *));

	if (pages == NULL) {
		pr_err("cannot vmalloc");
		retval = -1;
		goto cleanup;
	}

	down_read(&current->mm->mmap_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
	pinned_pages = pin_user_pages(buffer_start, npages, FOLL_WRITE, pages);
#else
	pinned_pages = pin_user_pages(buffer_start, npages, FOLL_WRITE, pages, NULL);
#endif
	up_read(&current->mm->mmap_lock);

	if (pinned_pages != npages) {
		pr_err("could not map all user pages");
		retval = -1;
		goto cleanup;
	}

	nid = page_to_nid(pages[0]); // Remap on the same NUMA node.

	hpt->ring_memory = vm_map_ram(pages, npages, nid);

	if (hpt->ring_memory == NULL) {
		pr_err("cannot vm_map_ram");
		retval = -1;
		goto cleanup;
	}

	hpt->mapped_pages = pages;
	hpt->num_mapped_pages = npages;

	return 0;

cleanup:

	if (pinned_pages > 0) {
		unpin_user_pages_dirty_lock(pages, pinned_pages, true);
	}

	if (pages) {
		vfree(pages);
	}

	return retval;
}

static int hpt_dbgfs_tun_create(struct hpt_dev *hpt, const char *name)
{
	struct dentry *tun_dir;

	tun_dir = debugfs_create_dir(name, hmi.hmi_dbgfs_root);
	if (IS_ERR(tun_dir)) {
		pr_err("Cannot create debugfs tunnel directory: %s (%ld)\n",
		       name, PTR_ERR(tun_dir));
		return PTR_ERR(tun_dir);
	}

	debugfs_create_u64(HPT_DBGFS_TX_RING_WRITE, 0400, tun_dir,
			   &hpt->tx_ring->write);
	debugfs_create_u64(HPT_DBGFS_TX_RING_READ, 0400, tun_dir,
			   &hpt->tx_ring->read);
	debugfs_create_u64(HPT_DBGFS_TX_RING_ERRS, 0400, tun_dir,
			   &hpt->hd_tx_errs);
	debugfs_create_u64(HPT_DBGFS_TX_RING_LEN_ZERO, 0400, tun_dir,
			   &hpt->hd_tx_len_zero);
	debugfs_create_u64(HPT_DBGFS_TX_RING_LEN_OVER, 0400, tun_dir,
			   &hpt->hd_tx_len_over);

	debugfs_create_u64(HPT_DBGFS_RX_RING_WRITE, 0400, tun_dir,
			   &hpt->rx_ring->write);
	debugfs_create_u64(HPT_DBGFS_RX_RING_READ, 0400, tun_dir,
			   &hpt->rx_ring->read);
	debugfs_create_u64(HPT_DBGFS_RX_RING_EMPTY, 0400, tun_dir,
			   &hpt->hd_rx_empty);
	debugfs_create_u64(HPT_DBGFS_RX_RING_LEN_ZERO, 0400, tun_dir,
			   &hpt->hd_rx_len_zero);
	debugfs_create_u64(HPT_DBGFS_RX_RING_LEN_OVER, 0400, tun_dir,
			   &hpt->hd_rx_len_over);
	debugfs_create_u64(HPT_DBGFS_RX_RING_PROC, 0400, tun_dir,
			   &hpt->hd_rx_called);
	debugfs_create_u64(HPT_DBGFS_RX_RING_NON_IP, 0400, tun_dir,
			   &hpt->hd_rx_non_ip);
	debugfs_create_u64(HPT_DBGFS_RX_RING_MEM_ERR, 0400, tun_dir,
			   &hpt->hd_rx_skb_alloc_err);
	debugfs_create_u64(HPT_DBGFS_RX_NETIF_DROP, 0400, tun_dir,
			   &hpt->hd_rx_netif_drop);

	hpt->hd_dbgfs_tun_dir = tun_dir;

	return 0;
}

static int hpt_ioctl_create(struct file *file, struct net *net,
			    uint32_t ioctl_num, unsigned long ioctl_param)
{
	struct net_device *net_dev = NULL;
	struct hpt_device_info dev_info;
	struct hpt_dev *hpt;
	int ret;

	pr_info("Creating hpt...\n");

	/* Check if there is already a dev created */
	if (file->private_data) {
		return -EINVAL;
	}

	/* Check the buffer size */
	if (_IOC_SIZE(ioctl_num) != sizeof(dev_info)) {
		return -EINVAL;
	}

	/* Copy hpt info from user space */
	if (copy_from_user(&dev_info, (void *)ioctl_param, sizeof(dev_info))) {
		return -EFAULT;
	}

	/* Check if name is zero-ended */
	if (strnlen(dev_info.name, sizeof(dev_info.name)) ==
	    sizeof(dev_info.name)) {
		pr_err("hpt.name not zero-terminated");
		return -EINVAL;
	}

	pr_info("Checks complete. Happy to create a device\n");

	net_dev = alloc_netdev(sizeof(struct hpt_dev), dev_info.name,
#ifdef NET_NAME_USER
			       NET_NAME_USER,
#endif
			       hpt_net_init);
	if (net_dev == NULL) {
		pr_err("error allocating device \"%s\"\n", dev_info.name);
		return -EBUSY;
	}

	dev_net_set(net_dev, net);

	hpt = netdev_priv(net_dev);

	init_waitqueue_head(&hpt->tx_busy);

	hpt->net_dev = net_dev;
	hpt->ring_buffer_items = dev_info.ring_buffer_items;

	// Bound the number of ring buffer elements so that 2x the number of items can't lead to address overflow
	if (hpt->ring_buffer_items > HPT_MAX_ITEMS) {
		pr_err("cannot allocate such a large HPT");
		ret = -EINVAL;
		goto clean_up;
	}

	/* Now we have how many items we need stored map the memory for the ring and wake flag */
	hpt->num_ring_memory =
		(sizeof(struct hpt_ring_buffer) * 2) +
		(hpt->ring_buffer_items * 2 * HPT_RB_ELEMENT_SIZE) + sizeof(uint8_t);

	/*
   * We derive the memory we need from the provided ring buffer size but we make sure that the mem_size provided by userspace should fit it
   * This doesn't improve security, but adds a second level of protection for userspace shooting itself in the foot by corrupting runtime memory.
   */
	if (dev_info.mem_size < hpt->num_ring_memory) {
		pr_err("the userspace memory provided does not have enough space to fit this ring and wake flag");
		ret = -EINVAL;
		goto clean_up;
	}

	pr_info("HPT memory: %zu %zu", hpt->ring_buffer_items,
		hpt->num_ring_memory);

	if (hpt_map_in_pages(hpt, &dev_info) != 0) {
		pr_err("could not map in userspace pages");
		ret = -EINVAL;
		goto clean_up;
	}

	pr_info("HPT allocated");

	hpt->tx_ring = (struct hpt_ring_buffer *)hpt->ring_memory;
	hpt->rx_ring = hpt->tx_ring + 1;
	hpt->tx_start = hpt_rb_tx_start(hpt->tx_ring, hpt->ring_buffer_items);
	hpt->rx_start = hpt_rb_rx_start(hpt->tx_ring, hpt->ring_buffer_items);
	hpt->kthread_needs_wake = hpt->ring_memory + hpt->num_ring_memory - sizeof(uint8_t);
	hpt->kthread_idle_jiffies = usecs_to_jiffies(dev_info.idle_usec);

	pr_info("set up pointers");

	strncpy(hpt->name, dev_info.name, HPT_NAMESIZE);

	pr_info("copied in name");

	// Kernel 5.16 and above call dev_addr_check to check MAC address
	// Since this is a virtual interface, set MAC address to all zeros
	pr_info("set MAC address to all zeros for virtual interfaces");
	unsigned char virtual_mac_addr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	eth_hw_addr_set(net_dev, virtual_mac_addr);

	ret = hpt_dbgfs_tun_create(hpt, hpt->name);
	if (ret)
		goto clean_up;

	ret = register_netdevice(net_dev);
	if (ret) {
		pr_err("error %i registering device \"%s\"\n", ret,
		       dev_info.name);
		goto clean_up;
	}

	/* Initialise the reader thread */
	init_waitqueue_head(&hpt->read_wait_queue);

	/* Launch the RX and epoll handling kthread */
	ret = hpt_run_thread(hpt);

	if (ret != 0) {
		pr_err("Couldn't start rx kernel thread: %i\n", ret);
		unregister_netdevice(net_dev);
		goto clean_up;
	}

	file->private_data = hpt;

	net_dev->needs_free_netdev = true;

	pr_info("HPT: Complete");

	return 0;

clean_up:
	if (hpt->ring_memory)
		hpt_unmap_pages(hpt);
	if (net_dev)
		free_netdev(net_dev);

	return ret;
}

static int hpt_ioctl_notify(struct file *file, struct net *net, uint32_t ioctl_num, unsigned long ioctl_param){

    struct hpt_dev *hpt = file->private_data;

    // Wake up the thread waiting for data
    wake_up_all(&hpt->read_wait_queue);

    return 0;
}

static long hpt_ioctl(struct file *file, uint32_t ioctl_num,
		      unsigned long ioctl_param)
{
	int ret = -EINVAL;
	struct net *net = NULL;

	pr_debug("IOCTL num=0x%0x param=0x%0lx\n", ioctl_num, ioctl_param);

	/*
	 * Switch according to the ioctl called
	 */
	switch (_IOC_NR(ioctl_num)) {
	case _IOC_NR(HPT_IOCTL_CREATE):
		rtnl_lock();
		net = current->nsproxy->net_ns;
		ret = hpt_ioctl_create(file, net, ioctl_num, ioctl_param);
		rtnl_unlock();
		break;
	case _IOC_NR(HPT_IOCTL_NOTIFY):
		ret = hpt_ioctl_notify(file, net, ioctl_num, ioctl_param);
		break;
	default:
		pr_debug("IOCTL default\n");
		break;
	}


	return ret;
}

/* Don't support legacy ioctl */
static long hpt_compat_ioctl(struct file *inode, uint32_t ioctl_num,
			     unsigned long ioctl_param)
{
	pr_debug("Not implemented.\n");
	return -EINVAL;
}

static const struct file_operations hpt_fops = {
	.owner = THIS_MODULE,
	.open = hpt_open,
	.release = hpt_release,
	.poll = hpt_poll,
	.unlocked_ioctl = hpt_ioctl,
	.compat_ioctl = hpt_compat_ioctl,
};

static struct miscdevice hpt_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = HPT_DEVICE,
	.fops = &hpt_fops,
};

static int __init hpt_init(void)
{
	struct dentry *root;
	int rc;

	root = debugfs_create_dir(HPT_DEVICE, NULL);
	if (IS_ERR(root)) {
		pr_err("Cannot create debugfs root dir: %ld\n", PTR_ERR(root));
		return PTR_ERR(root);
	}
		
	rc = misc_register(&hpt_misc);

	if (rc != 0) {
		pr_err("Misc registration failed\n");
		debugfs_remove_recursive(root);
		return rc;
	}
	hmi.hmi_dbgfs_root = root;
	
	return 0;
}

static void __exit hpt_exit(void)
{
	if (hmi.hmi_dbgfs_root)
		debugfs_remove_recursive(hmi.hmi_dbgfs_root);
	misc_deregister(&hpt_misc);
}

module_init(hpt_init);
module_exit(hpt_exit);
