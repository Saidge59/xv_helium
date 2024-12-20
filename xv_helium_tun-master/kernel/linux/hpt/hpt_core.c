#include <hpt/hpt_common.h>
#include "hpt_dev.h"
#include <linux/dma-mapping.h>
#include <linux/page-flags.h>
#include <linux/gfp.h>

MODULE_VERSION(HPT_VERSION);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Blake Loring");
MODULE_DESCRIPTION("High Performance TUN device");

struct hpt_mod_info hmi;

static struct device core_dev;
#define DMA_ALIGNMENT 4096 // Assume 4KB alignment for DMA requirements

static void hpt_free_buffers(struct hpt_dev *hpt);

static int hpt_kernel_thread(void *param)
{
	pr_info("Kernel RX thread started!\n");
	struct hpt_dev *dev = param;
	//size_t timeout = jiffies + dev->kthread_idle_jiffies;
	//const long schedule_timout = usecs_to_jiffies(HPT_KTHREAD_RESCHEDULE_INTERVAL);

	while (!kthread_should_stop()) {
		wait_event_interruptible(dev->read_wait_queue, dev->event_flag);
		spin_lock(&dev->buffer_lock);
		dev->event_flag = 0;
		spin_unlock(&dev->buffer_lock);
		// Process received packets
		hpt_net_rx(dev);
		// Additional tasks, e.g., transmitting processed packets
	}

	/*
	while (true) {
		// Wait for some idle time before commiting to sleeping
		if (time_after_eq(jiffies, timeout)) {
			STORE(dev->kthread_needs_wake, 1);
			// Go to sleep if there aren't any packets
			wait_event_interruptible(
				dev->read_wait_queue,
				hpt_rb_count(dev->rx_ring,
					     dev->ring_buffer_items) ||
					kthread_should_stop());
			STORE(dev->kthread_needs_wake, 0);
		} else {
			
			 // This short sleep will release the cpu to allow for other tasks to be run on it
			 // this is important or ksoftirqd will never process the packet backlogs
			schedule_timeout_interruptible(schedule_timout);
		}

		// If we got killed, abort the loop
		if (kthread_should_stop()) {
			pr_info("Kernel RX thread killed exiting RX loop\n");
			break;
		}

		// Consume any packet and if data was consumed, reset our idle timer
		if (hpt_net_rx(dev) > 0) {
			timeout = jiffies + dev->kthread_idle_jiffies;
		}
	}
*/
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

	hpt_free_buffers(hpt);

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
	hpt->pthread =
		kthread_create(hpt_kernel_thread, (void *)hpt, "%s", hpt->name);

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

//=====================================================================
static int hpt_allocate_buffers(struct hpt_dev *hpt)
{
    int i;

    for (i = 0; i < 1; i++) {

		hpt->buffers[i].data_combined = kmalloc(HPT_BUFFER_SIZE, GFP_KERNEL);
		if (!hpt->buffers[i].data_combined) {
			pr_err("Failed to allocate combined buffer %d\n", i);
			return -ENOMEM;
		}
		atomic_set(&hpt->buffers[i].in_use, 0);

	/*
        // Allocate data_in buffer
        hpt->buffers[i].data_in = kmalloc(HPT_BUFFER_SIZE + DMA_ALIGNMENT - 1, GFP_KERNEL);
        if (!hpt->buffers[i].data_in) {
            pr_err("Failed to allocate data_in buffer %d\n", i);
            return -ENOMEM;
        }
        hpt->buffers[i].aligned_data_in = PTR_ALIGN(hpt->buffers[i].data_in, DMA_ALIGNMENT);

        // Allocate data_out buffer
        hpt->buffers[i].data_out = kmalloc(HPT_BUFFER_SIZE + DMA_ALIGNMENT - 1, GFP_KERNEL);
        if (!hpt->buffers[i].data_out) {
            pr_err("Failed to allocate data_out buffer %d\n", i);
            kfree(hpt->buffers[i].data_in);
            return -ENOMEM;
        }
        hpt->buffers[i].aligned_data_out = PTR_ALIGN(hpt->buffers[i].data_out, DMA_ALIGNMENT);

        atomic_set(&hpt->buffers[i].in_use, 0);
        pr_info("Allocated buffers %d: data_in=%p, data_out=%p\n", i,
                hpt->buffers[i].aligned_data_in, hpt->buffers[i].aligned_data_out);
				*/
    }

    hpt->buffers_allocated = 1;
    spin_lock_init(&hpt->buffer_lock);
    pr_info("HPT buffers allocated successfully\n");
    return 0;
}

static void hpt_free_buffers(struct hpt_dev *hpt)
{
	int i;
	for (i = 0; i < 1; i++) {
		
		if (hpt->buffers[i].data_combined) {
        	kfree(hpt->buffers[i].data_combined);
			atomic_set(&hpt->buffers[i].in_use, 0);
   		}
		/*
		if (hpt->buffers[i].data_in) {
			dma_free_coherent(hpt->net_dev->dev.parent,
					  HPT_BUFFER_SIZE,
					  hpt->buffers[i].data_in,
					  hpt->buffers[i].dma_in_addr);
			hpt->buffers[i].data_in = NULL;
		}
		if (hpt->buffers[i].data_out) {
			dma_free_coherent(hpt->net_dev->dev.parent,
					  HPT_BUFFER_SIZE,
					  hpt->buffers[i].data_out,
					  hpt->buffers[i].dma_out_addr);
			hpt->buffers[i].data_out = NULL;
		}*/
	}
	hpt->buffers_allocated = 0;
	spin_unlock(&hpt->buffer_lock);
}

static int hpt_mmap(struct file *file, struct vm_area_struct *vma) {
    struct hpt_dev *hpt = file->private_data;
    unsigned long pfn;
    int buffer_idx;

    // Determine the buffer index based on vm_pgoff
    buffer_idx = vma->vm_pgoff;
    if (buffer_idx >= HPT_BUFFER_COUNT) {
        pr_err("Invalid buffer index: %d\n", buffer_idx);
        return -EINVAL;
    }

    // Validate the buffer
    if (!hpt->buffers[buffer_idx].data_combined) {
        pr_err("Combined buffer not allocated for index %d\n", buffer_idx);
        return -EINVAL;
    }

    // Check if the buffer is already in use
    if (atomic_read(&hpt->buffers[buffer_idx].in_use)) {
        pr_err("Buffer %d is already in use\n", buffer_idx);
        return -EBUSY;
    }

    // Calculate the PFN for the combined buffer
    pfn = virt_to_phys(hpt->buffers[buffer_idx].data_combined) >> PAGE_SHIFT;

    // Map the combined buffer to user space
    if (remap_pfn_range(vma, vma->vm_start, pfn, HPT_BUFFER_SIZE, vma->vm_page_prot)) {
        pr_err("Failed to map combined buffer: idx=%d pfn=%lx\n", buffer_idx, pfn);
        return -EFAULT;
    }

    // Mark the buffer as in use
    atomic_set(&hpt->buffers[buffer_idx].in_use, 1);

    pr_info("Mapped combined buffer for index %d\n", buffer_idx);
    return 0;
}


/*
static int hpt_mmap(struct file *file, struct vm_area_struct *vma) {
    struct hpt_dev *hpt = file->private_data;
    unsigned long pfn_encrypted, pfn_decrypted;
    int buffer_idx;

    buffer_idx = vma->vm_pgoff;
    if (buffer_idx >= HPT_BUFFER_COUNT) {
        pr_err("Invalid buffer index: %d\n", buffer_idx);
        return -EINVAL;
    }

    // Validate the buffers
    if (!hpt->buffers[buffer_idx].data_in || !hpt->buffers[buffer_idx].data_out) {
        pr_err("Buffers not allocated for index %d\n", buffer_idx);
        return -EINVAL;
    }

    // Check if the buffer is already in use
    if (atomic_read(&hpt->buffers[buffer_idx].in_use)) {
        pr_err("Buffer %d is already in use\n", buffer_idx);
        return -EBUSY;
    }

    // Calculate PFNs
    pfn_encrypted = virt_to_phys(hpt->buffers[buffer_idx].data_in) >> PAGE_SHIFT;
    pfn_decrypted = virt_to_phys(hpt->buffers[buffer_idx].data_out) >> PAGE_SHIFT;

    // Map the encrypted buffer
    if (remap_pfn_range(vma, vma->vm_start, pfn_encrypted, HPT_BUFFER_SIZE, vma->vm_page_prot)) {
        pr_err("Failed to map encrypted buffer: idx=%d pfn=%lx\n", buffer_idx, pfn_encrypted);
        return -EFAULT;
    }

    // Map the decrypted buffer
    
	if (remap_pfn_range(vma, vma->vm_start + HPT_BUFFER_SIZE, pfn_decrypted, HPT_BUFFER_SIZE, vma->vm_page_prot)) {
        pr_err("Failed to map decrypted buffer: idx=%d pfn=%lx\n", buffer_idx, pfn_decrypted);
        return -EFAULT;
    }

    // Mark the buffer as in use
    atomic_set(&hpt->buffers[buffer_idx].in_use, 1);

    pr_info("Mapped encrypted and decrypted buffers for index %d\n", buffer_idx);
    return 0;
}*/


/*
static int hpt_mmap(struct file *file, struct vm_area_struct *vma) {
	struct hpt_dev *hpt = file->private_data;
    unsigned long pfn_encrypted, pfn_decrypted;
    int buffer_idx;

    // Determine the buffer index
    buffer_idx = vma->vm_pgoff;
    if (buffer_idx >= HPT_BUFFER_COUNT)
        return -EINVAL;

	if (atomic_read(&hpt->buffers[buffer_idx].in_use))
		return -EBUSY;

    // Get the physical frame numbers for encrypted and decrypted buffers
    pfn_encrypted = virt_to_phys(hpt->buffers[buffer_idx].data_in) >> PAGE_SHIFT;
    pfn_decrypted = virt_to_phys(hpt->buffers[buffer_idx].data_out) >> PAGE_SHIFT;

    // Map both buffers to consecutive regions in user space
    if (remap_pfn_range(vma, vma->vm_start, pfn_encrypted, HPT_BUFFER_SIZE, vma->vm_page_prot))
        return -EFAULT;

    if (remap_pfn_range(vma, vma->vm_start + HPT_BUFFER_SIZE, pfn_decrypted, HPT_BUFFER_SIZE, vma->vm_page_prot))
        return -EFAULT;

	 // Mark the decrypted buffer as in use
	atomic_set(&hpt->buffers[buffer_idx].in_use, 1);

    return 0;
}
*/
/*
static struct hpt_dma_buffer *get_free_buffer(struct hpt_dev *hpt)
{
	int i;
	struct hpt_dma_buffer *buffer = NULL;
	spin_lock(&hpt->buffer_lock);
	for (i = 0; i < HPT_BUFFER_COUNT; i++) {
		if (atomic_cmpxchg(&hpt->buffers[i].in_use, 0, 1) == 0) {
			buffer = &hpt->buffers[i];
			break;
		}
	}
	spin_unlock(&hpt->buffer_lock);
	return buffer;
}

static void release_buffer(struct hpt_dev *hpt, dma_addr_t dma_in_addr)
{
	int i;
	spin_lock(&hpt->buffer_lock);
	for (i = 0; i < HPT_BUFFER_COUNT; i++) {
		if (hpt->buffers[i].dma_in_addr == dma_in_addr) {
			atomic_set(&hpt->buffers[i].in_use, 0);
			break;
		}
	}
	spin_unlock(&hpt->buffer_lock);
}
*/
//=====================================================================

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
/*
static int hpt_ioctl_create(struct file *file, struct net *net,
                            uint32_t ioctl_num, unsigned long ioctl_param)
{
    struct hpt_dev *hpt;
    int ret = 0;

    pr_info("Creating HPT device...\n");

    if (file->private_data) {
        pr_err("Device already created\n");
        return -EINVAL;
    }

    hpt = kzalloc(sizeof(struct hpt_dev), GFP_KERNEL);
    if (!hpt) {
        pr_err("Failed to allocate hpt_dev structure\n");
        return -ENOMEM;
    }

    hpt->buffers_allocated = 0;
    spin_lock_init(&hpt->buffer_lock);
    init_waitqueue_head(&hpt->read_wait_queue);

    // Allocate DMA buffers
    ret = hpt_allocate_buffers(hpt, &core_dev);
    if (ret) {
        pr_err("Failed to allocate buffers\n");
        kfree(hpt);
        return ret;
    }

    file->private_data = hpt;
    hpt->buffers_allocated = 1;

    pr_info("HPT device created successfully\n");
    return 0;
}
*/

static int hpt_ioctl_create(struct file *file, struct net *net,
			    uint32_t ioctl_num, unsigned long ioctl_param)
{
	struct net_device *net_dev = NULL;
	struct hpt_network_device_info dev_info;
	struct hpt_dev *hpt;
	int ret;

	pr_info("Creating hpt...\n");

	if (file->private_data) {
		return -EINVAL;
	}

	if (_IOC_SIZE(ioctl_num) != sizeof(dev_info)) {
		return -EINVAL;
	}

	if (copy_from_user(&dev_info, (void *)ioctl_param, sizeof(dev_info))) {
		return -EFAULT;
	}

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
	//hpt->ring_buffer_items = dev_info.ring_buffer_items;

	// Bound the number of ring buffer elements so that 2x the number of items can't lead to address overflow
	if (hpt->ring_buffer_items > HPT_MAX_ITEMS) {
		pr_err("cannot allocate such a large HPT");
		ret = -EINVAL;
		goto clean_up;
	}

	// Now we have how many items we need stored map the memory for the ring and wake flag 
	hpt->num_ring_memory =
		(sizeof(struct hpt_ring_buffer) * 2) +
		(hpt->ring_buffer_items * 2 * HPT_RB_ELEMENT_SIZE) +
		sizeof(uint8_t);

	
   //We derive the memory we need from the provided ring buffer size but we make sure that the mem_size provided by userspace should fit it
   //This doesn't improve security, but adds a second level of protection for userspace shooting itself in the foot by corrupting runtime memory.
   
	if (dev_info.mem_size < hpt->num_ring_memory) {
		pr_err("the userspace memory provided does not have enough space to fit this ring and wake flag");
		ret = -EINVAL;
		goto clean_up;
	}

	//pr_info("HPT memory: %zu %zu", hpt->ring_buffer_items, hpt->num_ring_memory);
/*
	if (hpt_map_in_pages(hpt, &dev_info) != 0) {
		pr_err("could not map in userspace pages");
		ret = -EINVAL;
		goto clean_up;
	}
*/

/*
	hpt->tx_ring = (struct hpt_ring_buffer *)hpt->ring_memory;
	hpt->rx_ring = hpt->tx_ring + 1;
	hpt->tx_start = hpt_rb_tx_start(hpt->tx_ring, hpt->ring_buffer_items);
	hpt->rx_start = hpt_rb_rx_start(hpt->tx_ring, hpt->ring_buffer_items);
	hpt->kthread_needs_wake =
		hpt->ring_memory + hpt->num_ring_memory - sizeof(uint8_t);
	hpt->kthread_idle_jiffies = usecs_to_jiffies(dev_info.idle_usec);
*/	

	pr_info("set up pointers");

	strncpy(hpt->name, dev_info.name, HPT_NAMESIZE);

	pr_info("copied in name");

	// Kernel 5.16 and above call dev_addr_check to check MAC address
	// Since this is a virtual interface, set MAC address to all zeros
	pr_info("set MAC address to all zeros for virtual interfaces");
	unsigned char virtual_mac_addr[6] = {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01
	};
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

	//Initialise the reader thread 
	init_waitqueue_head(&hpt->read_wait_queue);

	 //Launch the RX and epoll handling kthread 
	ret = hpt_run_thread(hpt);

	if (ret != 0) {
		pr_err("Couldn't start rx kernel thread: %i\n", ret);
		unregister_netdevice(net_dev);
		goto clean_up;
	}

	ret = hpt_allocate_buffers(hpt);
	if (ret)
		goto clean_up;

	file->private_data = hpt;

	net_dev->needs_free_netdev = true;

	pr_info("HPT: Complete");

	return 0;

clean_up:
	if (net_dev)
		free_netdev(net_dev);

	return ret;
}

/*
static int hpt_ioctl_notify(struct file *file, struct net *net,
			    uint32_t ioctl_num, unsigned long ioctl_param)
{
	struct hpt_dev *hpt = file->private_data;

	// Wake up the thread waiting for data
	wake_up_all(&hpt->read_wait_queue);

	return 0;
}
*/
static long hpt_ioctl(struct file *file, uint32_t ioctl_num,
		      unsigned long ioctl_param)
{
	int ret = -EINVAL;
	struct net *net = NULL;
	struct hpt_dev *hpt = file->private_data;

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
		spin_lock(&hpt->buffer_lock);
		hpt->event_flag = 1;
		spin_unlock(&hpt->buffer_lock);

		wake_up_interruptible(&hpt->read_wait_queue);
		//ret = hpt_ioctl_notify(file, net, ioctl_num, ioctl_param);
		break;
	case _IOC_NR(HPT_IOCTL_DESTROY):
		if (hpt->buffers_allocated) {
			hpt_free_buffers(hpt);
			return 0;
		}
		return -EINVAL;
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
	.mmap = hpt_mmap,
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

	// Initialize the dummy device
    dev_set_name(&core_dev, "hpt_core_device");
    device_initialize(&core_dev);
/*
	rc = hpt_allocate_buffers(&global_hpt_dev, &core_dev);
    if (rc) {
        pr_err("Failed to allocate buffers during initialization\n");
        put_device(&core_dev); // Release dummy device
        return rc;
    }
*/
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

	put_device(&core_dev); // Release core device
    pr_info("HPT driver exited\n");
}

module_init(hpt_init);
module_exit(hpt_exit);