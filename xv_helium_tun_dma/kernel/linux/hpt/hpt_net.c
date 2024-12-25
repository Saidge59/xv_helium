#include "hpt_dev.h"

#define WD_TIMEOUT 5 /*jiffies */
#define HPT_WAIT_RESPONSE_TIMEOUT 300 /* 3 seconds */

struct hpt_dev *hpt_device;

/*
 * Open and close
 */
static int hpt_net_open(struct net_device *dev)
{
	netif_start_queue(dev);
	netif_carrier_on(dev);

	return 0;
}

static int hpt_net_release(struct net_device *dev)
{
	netif_stop_queue(dev); /* can't transmit any more */
	netif_carrier_off(dev);
	return 0;
}

/*
 * Configuration changes (passed on by ifconfig)
 */
static int hpt_net_config(struct net_device *dev, struct ifmap *map)
{
	/* can't act on a running interface */
	if (dev->flags & IFF_UP) {
		return -EBUSY;
	}

	/* ignore other fields */
	return 0;
}

/*
 * Transmit a packet (called by the kernel)
 */
static int hpt_net_tx(struct sk_buff *skb, struct net_device *dev)
{
	if(!dev)
	{
		pr_err("hpt is null\n");
		return NETDEV_TX_OK;
	}

	size_t start = hpt_device->ring_buffer_items >> 1;
	size_t end = hpt_device->ring_buffer_items;

	for(int i = start; i < end; i++)
    {
    	struct hpt_dma_buffer *buffer = &hpt_device->buffers[i];
        hpt_data_info_t *data_info = (hpt_data_info_t *)buffer->data_combined;
        uint8_t *data = (uint8_t *)data_info + sizeof(hpt_data_info_t);

        if(ACQUIRE(&data_info->in_use)) continue;

		if(skb->len > HPT_BUFFER_SIZE - sizeof(hpt_data_info_t))
		{
			pr_err("Too big a packet for write\n");
			goto drop;
		}

		memcpy(data, skb->data, skb->len);
		STORE(&data_info->in_use, 1);
		data_info->size = skb->len;

		dev_kfree_skb(skb);
		
		break;
    }

	return NETDEV_TX_OK;

drop:
	/* Free skb and update statistics */
	dev_kfree_skb(skb);

	return NETDEV_TX_OK;
}

size_t hpt_net_rx(struct hpt_dev *hpt)
{
    struct net_device *dev = hpt->net_dev;
    struct sk_buff *skb;
    size_t num_processed = 0;
    int ret;
    u8 ip_version;

	size_t start = 0;
	size_t end = hpt->ring_buffer_items >> 1;

    for(int i = start; i < end; i++) 
	{
        struct hpt_dma_buffer *buffer = &hpt->buffers[i];
		if(!buffer) continue;

		hpt_data_info_t *data_info = (hpt_data_info_t *)buffer->data_combined;
        //if(!buffer || !atomic_read(&buffer->in_use)) continue;

        if(!ACQUIRE(&data_info->in_use) || !ACQUIRE(&data_info->ready_flag_rx)) continue;

		uint8_t *data = (uint8_t *)data_info + sizeof(hpt_data_info_t);
		//pr_info("Buf %02x, %02x, %02x, %02x\n", data[0], data[1], data[2], data[3]);

		size_t len = ((uint16_t)data[2] << 8) | data[3];
		//pr_info("The index %d, len %zu\n", i, len);

		if(unlikely(len == 0 || len > HPT_BUFFER_SIZE)) {
		    dev->stats.rx_dropped++;
			//atomic_set(&buffer->in_use, 0);
			STORE(&data_info->in_use, 0);
        	continue;
        }
		//pr_info("The packet length is %zu\n", len);

        skb = netdev_alloc_skb(dev, len);
        if(unlikely(!skb)) {
            dev->stats.rx_dropped++;
        	//atomic_set(&buffer->in_use, 0);
			STORE(&data_info->in_use, 0);
			pr_err("Could not allocate memory to transmit a packet\n");
        	continue;
        }

        // Copy the decrypted data into the SKB
        memcpy(skb_put(skb, len), data, len);
        //atomic_set(&buffer->in_use, 0);
		STORE(&data_info->in_use, 0);
		STORE(&data_info->ready_flag_rx, 0);

        // Check the IP version (from the start of the buffer)
        ip_version = skb->len ? (skb->data[0] >> 4) : 0;

        if(unlikely(!(ip_version == 4 || ip_version == 6))) {
            dev_kfree_skb(skb);
            dev->stats.rx_dropped++;
			pr_err("Drop packets that are not IPv4 or IPv6\n");
        	continue;
        }

        // Set SKB headers
        skb_reset_mac_header(skb);
        skb->protocol = ip_version == 4 ? htons(ETH_P_IP) : htons(ETH_P_IPV6);
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        skb_reset_network_header(skb);
        skb_probe_transport_header(skb);

        // Send the SKB to the network stack
        ret = netif_rx(skb);
		//pr_info("The packet send\n");

        // Update statistics
        dev->stats.rx_bytes += len;
        dev->stats.rx_packets++;
        num_processed++;
    }

	return num_processed;
}

#ifdef HAVE_TX_TIMEOUT_TXQUEUE
static void hpt_net_tx_timeout(struct net_device *dev, unsigned int txqueue)
#else
static void hpt_net_tx_timeout(struct net_device *dev)
#endif
{
	pr_debug("Transmit timeout at %ld, latency %ld\n", jiffies,
		 jiffies - dev_trans_start(dev));
	dev->stats.tx_errors++;
	netif_wake_queue(dev);
}

static int hpt_net_change_mtu(struct net_device *dev, int new_mtu)
{
	return -EINVAL;
}

static void hpt_net_change_rx_flags(struct net_device *netdev, int flags)
{
	return;
}

/**
 * Point to point interfaces don't need to strip headers
 * so we leave this function empty.
 */
static int hpt_net_header(struct sk_buff *skb, struct net_device *dev,
			  unsigned short type, const void *daddr,
			  const void *saddr, uint32_t len)
{
	return 0;
}

/**
 * Change the link carrier state from up to down by ip link set dev ... up
 */
static int hpt_net_change_carrier(struct net_device *dev, bool new_carrier)
{
	if (new_carrier) {
		netif_carrier_on(dev);
	} else {
		netif_carrier_off(dev);
	}
	return 0;
}

static const struct header_ops hpt_net_header_ops = {
	.create = hpt_net_header,
	.parse = eth_header_parse,
	.cache = NULL, /* disable caching */
};

static const struct net_device_ops hpt_net_netdev_ops = {
	.ndo_open = hpt_net_open,
	.ndo_stop = hpt_net_release,
	.ndo_set_config = hpt_net_config,
	.ndo_change_rx_flags = hpt_net_change_rx_flags,
	.ndo_start_xmit = hpt_net_tx,
	.ndo_change_mtu = hpt_net_change_mtu,
	.ndo_tx_timeout = hpt_net_tx_timeout,
	.ndo_change_carrier = hpt_net_change_carrier,
};

static void hpt_get_drvinfo(struct net_device *dev,
			    struct ethtool_drvinfo *info)
{
	strscpy(info->version, HPT_VERSION, sizeof(info->version));
	strscpy(info->driver, "hpt", sizeof(info->driver));
}

static const struct ethtool_ops hpt_net_ethtool_ops = {
	.get_drvinfo = hpt_get_drvinfo,
	.get_link = ethtool_op_get_link,
};

void hpt_net_init(struct net_device *dev)
{
	/* Point-to-Point TUN Device */
	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
	/* Zero header length */
	dev->type = ARPHRD_NONE;
	dev->hard_header_len = 0;
	dev->addr_len = 0;

	dev->mtu = HPT_MTU;;
	dev->max_mtu = HPT_MTU;
	dev->min_mtu = HPT_MTU;

	dev->netdev_ops = &hpt_net_netdev_ops;
	dev->header_ops = &hpt_net_header_ops;
	dev->ethtool_ops = &hpt_net_ethtool_ops;
	dev->watchdog_timeo = WD_TIMEOUT;
}
