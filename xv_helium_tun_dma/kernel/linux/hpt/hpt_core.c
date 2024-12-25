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
static void hpt_free_buffers(struct hpt_dev *hpt);

static int hpt_kernel_thread(void *param)
{
	pr_info("Kernel RX thread started!\n");
	struct hpt_dev *dev = param;

	while (!kthread_should_stop()) {
		wait_event_interruptible(dev->read_wait_queue, dev->event_flag);
		spin_lock(&dev->buffer_lock);
		dev->event_flag = 0;
		spin_unlock(&dev->buffer_lock);
		hpt_net_rx(dev);
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

	hpt_free_buffers(dev);

	pr_info("/dev/hpt closed\n");

	rtnl_unlock();
	return 0;
}

static int hpt_allocate_buffers(struct hpt_dev *hpt)
{
	if(hpt->ring_buffer_items > HPT_BUFFER_COUNT)
	{
        pr_err("Too many elements for buffer'\n");
        return -EINVAL;
    }

    for (int i = 0; i < hpt->ring_buffer_items; i++) 
	{
		struct hpt_dma_buffer *buffer = &hpt->buffers[i];
		buffer->data_combined = dma_alloc_coherent(&hpt->pdev->dev,
                                                 HPT_BUFFER_SIZE,
                                                 &buffer->dma_handle,
                                                 GFP_KERNEL);

		if (!buffer->data_combined) {
			pr_err("Failed to allocate combined buffer %d\n", i);
			return -ENOMEM;
		}
		hpt_data_info_t *data_info = (hpt_data_info_t *)buffer->data_combined;
		STORE(&data_info->in_use, 0);
	}

	return 0;
}

static void hpt_free_buffers(struct hpt_dev *hpt)
{
	int i;
	for (i = 0; i < hpt->ring_buffer_items; i++) 
	{
		struct hpt_dma_buffer *buffer = &hpt->buffers[i];

		if (buffer->data_combined) 
		{
			dma_free_coherent(hpt->device, 
								HPT_BUFFER_SIZE,
                      			buffer->data_combined, 
					  			buffer->dma_handle);
   		}
	}
}

static int hpt_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct hpt_dev *dev = file->private_data;
	int buffer_idx = vma->vm_pgoff;
	struct hpt_dma_buffer *buffer = &dev->buffers[buffer_idx];
    unsigned long pfn = buffer->dma_handle >> PAGE_SHIFT;

    if (buffer_idx >= HPT_BUFFER_COUNT) 
	{
        pr_err("Invalid buffer index: %d\n", buffer_idx);
        return -EINVAL;
    }

    // Validate the buffer
    if (!buffer->data_combined) 
	{
        pr_err("Combined buffer not allocated for index %d\n", buffer_idx);
        return -EINVAL;
    }

	hpt_data_info_t *data_info = (hpt_data_info_t *)buffer->data_combined;

	// Check if the buffer is already in use
	if(ACQUIRE(&data_info->in_use))
	{
        pr_err("Buffer %d is already in use\n", buffer_idx);
        return -EBUSY;
    }

    // Remap the DMA buffer to user space
    if (remap_pfn_range(vma, vma->vm_start, pfn, HPT_BUFFER_SIZE, vma->vm_page_prot))
        return -EAGAIN;

	// Mark the buffer as in use
    pr_info("Mapped combined buffer for index %d, addr %p\n", buffer_idx, buffer->data_combined);

    return 0;
}

static int hpt_ioctl_create(struct file *file, struct net *net,
			    uint32_t ioctl_num, unsigned long ioctl_param)
{
	struct net_device *net_dev = NULL;
	struct hpt_net_device_info net_dev_info;
	struct hpt_dev *hpt;
	int ret;

	pr_info("Creating hpt...\n");

	if (_IOC_SIZE(ioctl_num) != sizeof(net_dev_info)) {
		pr_err("Error check the buffer size\n");
		return -EINVAL;
	}

	if (copy_from_user(&net_dev_info, (void *)ioctl_param, sizeof(net_dev_info))) {
		pr_err("Error copy hpt info from user space\n");
		return -EFAULT;
	}

	if (strnlen(net_dev_info.name, sizeof(net_dev_info.name)) ==
	    sizeof(net_dev_info.name)) {
		pr_err("hpt.name not zero-terminated");
		return -EINVAL;
	}

	net_dev = alloc_netdev(sizeof(struct hpt_dev), net_dev_info.name,
#ifdef NET_NAME_USER
			       NET_NAME_USER,
#endif
			       hpt_net_init);
	if (net_dev == NULL) {
		pr_err("error allocating device \"%s\"\n", net_dev_info.name);
        return -EBUSY;
	}

	dev_net_set(net_dev, net);

	hpt = file->private_data;

	init_waitqueue_head(&hpt->tx_busy);

	hpt->net_dev = net_dev;
	pr_info("Set net_dev\n");

	strncpy(hpt->name, net_dev_info.name, HPT_NAMESIZE);

	if(net_dev_info.ring_buffer_items >= HPT_BUFFER_COUNT)
	{
		pr_err("Does not have enough space %zu\n", net_dev_info.ring_buffer_items);
		goto clean_up;
	}
	hpt->ring_buffer_items = net_dev_info.ring_buffer_items;
	pr_info("Copied name %s and size %zu\n", hpt->name, hpt->ring_buffer_items);

	unsigned char virtual_mac_addr[6] = {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01
	};
	eth_hw_addr_set(net_dev, virtual_mac_addr);
	pr_info("Set MAC address for virtual interfaces\n");

	ret = register_netdevice(net_dev);
	if (ret) {
		pr_err("error %i registering device \"%s\"\n", ret, net_dev_info.name);
		goto clean_up;
	}

	//Initialise the reader thread 
	init_waitqueue_head(&hpt->read_wait_queue);

	ret = hpt_run_thread(hpt);
	if (ret != 0) {
		pr_err("Couldn't start rx kernel thread: %i\n", ret);
		unregister_netdevice(net_dev);
		goto clean_up;
	}

	net_dev->needs_free_netdev = true;

	ret = hpt_allocate_buffers(hpt);
	if (ret != 0) {
		pr_err("Failed to allocate DMA buffer\n");
        ret = -ENOMEM;
        goto clean_up;
	}

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
	/*if(hpt_device->buffer_base)
	{
		dma_free_coherent(hpt_device->device, HPT_ALLOC_SIZE * 2,
                      hpt_device->buffer_base, hpt_device->dma_handle);
	}*/
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