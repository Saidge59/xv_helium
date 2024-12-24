#include <hpt/hpt_common.h>
#include "hpt_dev.h"
#include <linux/dma-mapping.h>
#include <linux/page-flags.h>
#include <linux/gfp.h>


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/dma-mapping.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>  // Add this

MODULE_VERSION(HPT_VERSION);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Blake Loring");
MODULE_DESCRIPTION("High Performance TUN device");

struct hpt_mod_info hmi;

//static struct device core_dev;
extern struct hpt_dev *hpt_device;
void copy_hpt_dev(struct hpt_dev *to, const struct hpt_dev *from);
//static void hpt_free_buffers(struct hpt_dev *hpt);

/*static unsigned int hpt_poll(struct file *file,
			     struct poll_table_struct *poll_table)
{
	struct hpt_dev *dev = file->private_data;

	unsigned int mask = 0;

	if (dev) {
		poll_wait(file, &dev->tx_busy, poll_table);
		if (hpt_rb_count(dev->tx_ring, dev->ring_buffer_items)) {
			mask |= POLLIN | POLLRDNORM;
		}
	}

	return mask;
}

//=====================================================================
static int hpt_allocate_buffers(struct hpt_dev *hpt)
{
    int i;

    for (i = 0; i < HPT_BUFFER_COUNT; i++) {

		hpt->buffers[i].data_combined = vmalloc_user(HPT_BUFFER_SIZE);//kmalloc(HPT_BUFFER_SIZE, GFP_KERNEL);
		if (!hpt->buffers[i].data_combined) {
			pr_err("Failed to allocate combined buffer %d\n", i);
			return -ENOMEM;
		}
		atomic_set(&hpt->buffers[i].in_use, 0);
    }

    hpt->buffers_allocated = 1;
    spin_lock_init(&hpt->buffer_lock);
    pr_info("HPT buffers allocated successfully\n");
    return 0;
}

static void hpt_free_buffers(struct hpt_dev *hpt)
{
	int i;
	for (i = 0; i < HPT_BUFFER_COUNT; i++) {
		
		if (hpt->buffers[i].data_combined) {
        	//kfree(hpt->buffers[i].data_combined);
			vfree(hpt->buffers[i].data_combined);
			atomic_set(&hpt->buffers[i].in_use, 0);
   		}
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
    //pfn = virt_to_phys(hpt->buffers[buffer_idx].data_combined) >> PAGE_SHIFT;
	pfn = vmalloc_to_pfn(hpt->buffers[buffer_idx].data_combined);

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
}*/

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

	pr_info("Kernel RX thread stopped!\n");
	return 0;
}

static inline bool hpt_capable(void)
{
	return capable(CAP_NET_ADMIN);
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

static int hpt_open(struct inode *inode, struct file *file)
{
	pr_info("HPT open!\n");

    //struct hpt_dev *dev = container_of(inode->i_cdev, struct hpt_dev, cdev);
    //file->private_data = dev;
	file->private_data = hpt_device;

	int ret;
	
	ret = security_tun_dev_create();
	if (ret < 0) {
		pr_info("Cannot create tun_dev\n");
		return ret;
	}

	if (!hpt_capable()) {
		return -EINVAL;
	}
	
	pr_info("/dev/hpt opened\n");
    return 0;
}

static int hpt_release(struct inode *inode, struct file *file)
{
	pr_info("HPT close!\n");

    struct hpt_dev *dev = NULL;

	rtnl_lock();

	dev = file->private_data;

	if (!dev) {
		pr_err("Cannot free unallocated device");
	}

	//hpt_free_buffers(dev);

	/*if (hpt->hd_dbgfs_tun_dir)
		debugfs_remove_recursive(hpt->hd_dbgfs_tun_dir);*/

	if (dev->pthread != NULL) {
		kthread_stop(dev->pthread);
		dev->pthread = NULL;
	}

	pr_info("Stopped pthread\n");

	if(dev->net_dev != NULL)
	{
		pr_info("unregister_netdevice\n");
		unregister_netdevice(dev->net_dev);
	}

	pr_info("/dev/hpt closed\n");

	rtnl_unlock();
	return 0;
}

static int hpt_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct hpt_dev *dev = file->private_data;
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long pfn = dev->dma_handle >> PAGE_SHIFT;

    // Ensure the requested size does not exceed the buffer size
    if (size > HPT_ALLOC_SIZE * 2)
        return -EINVAL;

    // Remap the DMA buffer to user space
    if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot))
        return -EAGAIN;

    return 0;
}

void copy_hpt_dev(struct hpt_dev *to, const struct hpt_dev *from) {
    strncpy(to->name, from->name, HPT_NAMESIZE);
    to->class = from->class;
    to->device = from->device;
    to->cdev = from->cdev; 
    to->devt = from->devt;
    to->pdev = from->pdev;
}

static int hpt_ioctl_create(struct file *file, struct net *net,
			    uint32_t ioctl_num, unsigned long ioctl_param)
{
	struct net_device *net_dev = NULL;
	struct hpt_dev *hpt;
	int ret;

	pr_info("Creating hpt...\n");

	net_dev = alloc_netdev(sizeof(struct hpt_dev), HPT_DEVICE,
#ifdef NET_NAME_USER
			       NET_NAME_USER,
#endif
			       hpt_net_init);
	if (net_dev == NULL) {
		pr_err("error allocating device \"%s\"\n", HPT_DEVICE);
		return -EBUSY;
	}

	dev_net_set(net_dev, net);

	//hpt = netdev_priv(net_dev);
	//memcpy(hpt, file->private_data, sizeof(struct hpt_dev));
	hpt = file->private_data;
	//copy_hpt_dev(hpt, file->private_data);


	init_waitqueue_head(&hpt->tx_busy);

	hpt->net_dev = net_dev;
	pr_info("Set net_dev\n");

	//hpt->ring_buffer_items = dev_info.ring_buffer_items;
/*
	if (hpt->ring_buffer_items > HPT_MAX_ITEMS) {
		pr_err("cannot allocate such a large HPT");
		ret = -EINVAL;
		goto clean_up;
	}

	hpt->num_ring_memory =
		(sizeof(struct hpt_ring_buffer) * 2) +
		(hpt->ring_buffer_items * 2 * HPT_RB_ELEMENT_SIZE) +
		sizeof(uint8_t);

	pr_info("set up pointers");
*/
	strncpy(hpt->name, HPT_DEVICE, HPT_NAMESIZE);

	pr_info("Copied in name\n");

	pr_info("Set MAC address for virtual interfaces\n");
	unsigned char virtual_mac_addr[6] = {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01
	};
	eth_hw_addr_set(net_dev, virtual_mac_addr);

	/*ret = hpt_dbgfs_tun_create(hpt, hpt->name);
	if (ret)
		goto clean_up;
*/

	ret = register_netdevice(net_dev);
	if (ret) {
		pr_err("error %i registering device \"%s\"\n", ret, HPT_DEVICE);
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

	net_dev->needs_free_netdev = true;

	// Allocate DMA buffer using platform device
    hpt->buffer_base = dma_alloc_coherent(&hpt->pdev->dev,
                                                 HPT_ALLOC_SIZE * 2,
                                                 &hpt->dma_handle,
                                                 GFP_KERNEL);
    
    if (!hpt->buffer_base) {
        pr_err("Failed to allocate DMA buffer\n");
        ret = -ENOMEM;
        goto clean_up;
    }
	hpt->ring_tx = (struct ring_buffer *)hpt->buffer_base;
	hpt->ring_rx = (struct ring_buffer *)hpt->buffer_base + (HPT_ALLOC_SIZE / sizeof(struct ring_buffer));

	pr_info("HPT: Complete");

	return 0;

clean_up:
	if (net_dev)
		free_netdev(net_dev);

	return ret;
}

static long hpt_ioctl(struct file *file, uint32_t ioctl_num,
		      unsigned long ioctl_param)
{
	int ret = -EINVAL;
	struct net *net = NULL;
	struct hpt_dev *hpt = file->private_data;

	//pr_info("IOCTL num=0x%0x param=0x%0lx\n", ioctl_num, ioctl_param);

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
		ret = 0;
		//ret = hpt_ioctl_notify(file, net, ioctl_num, ioctl_param);
		break;
	default:
		pr_info("IOCTL default\n");
		break;
	}

	return ret;
}

static struct file_operations hpt_fops = {
    .owner = THIS_MODULE,
    .open = hpt_open,
    .release = hpt_release,
    .mmap = hpt_mmap,
	.unlocked_ioctl = hpt_ioctl,
};

static int __init hpt_init(void)
{
    int ret;

    pr_info("Initializing module\n");

    hpt_device = kzalloc(sizeof(struct hpt_dev), GFP_KERNEL);
    if (!hpt_device)
        return -ENOMEM;

    // Allocate character device numbers
    ret = alloc_chrdev_region(&hpt_device->devt, 0, 1, HPT_DEVICE);
    if (ret) {
        pr_err("Failed to allocate chrdev region\n");
        goto err_free_dev;
    }

    // Initialize character device
    cdev_init(&hpt_device->cdev, &hpt_fops);
    hpt_device->cdev.owner = THIS_MODULE;
    ret = cdev_add(&hpt_device->cdev, hpt_device->devt, 1);
    if (ret) {
        pr_err("Failed to add cdev\n");
        goto err_unreg_chrdev;
    }

    // Create device class
    hpt_device->class = class_create(HPT_DEVICE);
    if (IS_ERR(hpt_device->class)) {
        pr_err("Failed to create class\n");
        ret = PTR_ERR(hpt_device->class);
        goto err_del_cdev;
    }

    // Create parent platform device first
    struct platform_device *pdev;
    pdev = platform_device_register_simple(HPT_DEVICE, -1, NULL, 0);
    if (IS_ERR(pdev)) {
        pr_err("Failed to register platform device\n");
        ret = PTR_ERR(pdev);
        goto err_del_cdev;
    }

    // Create device with platform device as parent
    hpt_device->device = device_create(hpt_device->class, &pdev->dev,
                                      hpt_device->devt, NULL, HPT_DEVICE);
    if (IS_ERR(hpt_device->device)) {
        pr_err("Failed to create device\n");
        ret = PTR_ERR(hpt_device->device);
        goto err_destroy_class;
    }

    // Set DMA mask with parent device
    ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
    if (ret) {
        pr_err("Failed to set DMA mask\n");
        goto err_destroy_device;
    }

    // Store platform device
    hpt_device->pdev = pdev;

    pr_info("DMA buffer allocated successfully\n");
    //mutex_init(&hpt_device->lock);

	pr_info("Init HPT!\n");
    return 0;

err_destroy_device:
    platform_device_unregister(hpt_device->pdev);
    device_destroy(hpt_device->class, hpt_device->devt);
err_destroy_class:
    platform_device_unregister(hpt_device->pdev);
    class_destroy(hpt_device->class);
err_del_cdev:
    cdev_del(&hpt_device->cdev);
err_unreg_chrdev:
    unregister_chrdev_region(hpt_device->devt, 1);
err_free_dev:
    kfree(hpt_device);
    pr_err("Module initialization failed\n");
    return ret;
}

static void __exit hpt_exit(void)
{
	if(hpt_device->buffer_base)
	{
		dma_free_coherent(hpt_device->device, HPT_ALLOC_SIZE * 2,
                      hpt_device->buffer_base, hpt_device->dma_handle);
	}
    platform_device_unregister(hpt_device->pdev);
    device_destroy(hpt_device->class, hpt_device->devt);
    class_destroy(hpt_device->class);
    cdev_del(&hpt_device->cdev);
    unregister_chrdev_region(hpt_device->devt, 1);
    kfree(hpt_device);
	pr_info("Exit HPT!\n");
}

module_init(hpt_init);
module_exit(hpt_exit);