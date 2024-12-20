#include "hpt_dev.h"

#define WD_TIMEOUT 5 /*jiffies */
#define HPT_WAIT_RESPONSE_TIMEOUT 300 /* 3 seconds */

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
	return NETDEV_TX_OK;
	/*
	struct hpt_dev *hpt = netdev_priv(dev);
	unsigned int len = skb->len;

	if (!len || len > HPT_RB_ELEMENT_USABLE_SPACE) {
		if (len)
			hpt->hd_tx_len_over++;
		else
			hpt->hd_tx_len_zero++;
		goto drop;
	}

	if (unlikely(hpt_rb_tx(hpt->tx_ring, hpt->ring_buffer_items,
			       hpt->tx_start, skb->data, len) != 0)) {
		hpt->hd_tx_errs++;
		goto drop;
	}

	dev_kfree_skb(skb);
	dev->stats.tx_bytes += len;
	dev->stats.tx_packets++;

	// Wake up the EPOLL
	wake_up_interruptible(&hpt->tx_busy);

	return NETDEV_TX_OK;

drop:
	dev_kfree_skb(skb);
	dev->stats.tx_dropped++;

	return NETDEV_TX_OK;
	*/
}

size_t hpt_net_rx(struct hpt_dev *hpt)
{
    struct net_device *dev = hpt->net_dev;
    struct sk_buff *skb;
    size_t num_processed = 0;
    int ret;
    u8 ip_version;

	pr_info("Processed the hpt_net_rx\n");

    for (int i = 0; i < 1; i++) {
        struct hpt_dma_buffer *buffer = &hpt->buffers[i];

        // Check if the buffer is in use
        if (buffer == NULL || !atomic_read(&buffer->in_use)) {
			pr_err("Skip buffers not marked as in use\n");
            continue;
        }

		pr_info("buffer: %02x, %02x, %02x, %02x\n", *(uint8_t *)buffer->data_combined, *((uint8_t *)buffer->data_combined+1),*((uint8_t *)buffer->data_combined+2),*((uint8_t *)buffer->data_combined+3));

        hpt->hd_rx_called++;

		size_t len = (((uint8_t*)buffer->data_combined)[2] << 8) | ((uint8_t*)buffer->data_combined)[3];
		if (unlikely(len == 0 || len > HPT_BUFFER_SIZE)) {
            if (len)
                hpt->hd_rx_len_over++;
            else
                hpt->hd_rx_len_zero++;
            dev->stats.rx_dropped++;
            atomic_set(&buffer->in_use, 0); // Mark the buffer as free
			pr_err("Skip buffers wrong len\n");
            continue;
        }
		pr_info("The packet length is %zu\n", len);

        skb = netdev_alloc_skb(dev, len);
        if (unlikely(!skb)) {
            dev->stats.rx_dropped++;
            hpt->hd_rx_skb_alloc_err++;
            atomic_set(&buffer->in_use, 0); // Mark the buffer as free
			pr_err("Could not allocate memory to transmit a packet\n");
            continue;
        }
		pr_info("netdev_alloc_skb");

        // Copy the decrypted data into the SKB
        memcpy(skb_put(skb, len), buffer->data_combined, len);
		pr_info("memcpy");

        // Mark the buffer as free after use
        atomic_set(&buffer->in_use, 0);

        // Check the IP version (from the start of the buffer)
        ip_version = skb->len ? (skb->data[0] >> 4) : 0;

        if (unlikely(!(ip_version == 4 || ip_version == 6))) {
            dev_kfree_skb(skb);
            dev->stats.rx_dropped++;
            hpt->hd_rx_non_ip++;
			pr_err("Drop packets that are not IPv4 or IPv6\n");
            continue;
        }
		pr_info("ip_version");

        // Set SKB headers
        skb_reset_mac_header(skb);
        skb->protocol = ip_version == 4 ? htons(ETH_P_IP) : htons(ETH_P_IPV6);
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        skb_reset_network_header(skb);
        skb_probe_transport_header(skb);
		pr_info("skb_probe_transport_header");

        // Send the SKB to the network stack
        ret = netif_rx(skb);
		pr_info("netif_rx");

        if (unlikely(ret == NET_RX_DROP)) {
            hpt->hd_rx_netif_drop++;
        }

        // Update statistics
        dev->stats.rx_bytes += len;
        dev->stats.rx_packets++;
        num_processed++;
    }

	return num_processed;
}


/*
size_t hpt_net_rx(struct hpt_dev *hpt)
{
	struct net_device *dev = hpt->net_dev;
	struct hpt_ring_buffer_element *elem;
	struct hpt_ring_buffer *ring;
	struct sk_buff *skb;
	size_t num, i, len;
	int ret;
	u8 ip_version;

	ring =  hpt->rx_ring;

	num = hpt_rb_count(ring, hpt->ring_buffer_items);

	for (i = 0; i < num; i++) {
		elem = hpt_rb_rx(ring, hpt->ring_buffer_items,
				 hpt->rx_start);

		hpt->hd_rx_called++;

		// Userspace can corrupt the ring at any time
		if (unlikely(!elem)) {
			hpt->hd_rx_empty++;
			break;
		}

		len = elem->len;

		// Check that the length is within bounds at the time we cache the value
		if (unlikely(len == 0 || len > HPT_RB_ELEMENT_USABLE_SPACE)) {
			if (len)
				hpt->hd_rx_len_over++;
			else
				hpt->hd_rx_len_zero++;
			dev->stats.rx_dropped++;
			hpt_rm_cur_ring_pkt(ring, elem);
			continue;
		}

		skb = netdev_alloc_skb(dev, len);

		// Could not allocate memory to transmit a packet 
		if (unlikely(!skb)) {
			// If we have to drop a packet due to memory still increment the read header 
			dev->stats.rx_dropped++;
			hpt->hd_rx_skb_alloc_err++;
			hpt_rm_cur_ring_pkt(ring, elem);
			continue;
		}

		// Copy the packet into the SKB 
		memcpy(skb_put(skb, len), elem->data, len);

		// Now the ring element is free to be used again 
		hpt_rm_cur_ring_pkt(ring, elem);

		// Extract the IP version from the start of the packet (IHL) and drop if it's not IPv4 or IPv6 
		ip_version = skb->len ? (skb->data[0] >> 4) : 0;

		// Drop packets that are not IPv4 or IPv6 
		if (unlikely(!(ip_version == 4 || ip_version == 6))) {
			dev_kfree_skb(skb);
			dev->stats.rx_dropped++;
			hpt->hd_rx_non_ip++;
			continue;
		}

		// Create SKB headers for this new packet. The SKB will work out its headers from the IP packet data. 
		skb_reset_mac_header(skb);

		skb->protocol =
			ip_version == 4 ? htons(ETH_P_IP) : htons(ETH_P_IPV6);
		skb->ip_summed = CHECKSUM_UNNECESSARY;

		skb_reset_network_header(skb);
		skb_probe_transport_header(skb);

		// Call netif interface 
		ret = netif_rx(skb);

		if (unlikely(ret == NET_RX_DROP)) {
			hpt->hd_rx_netif_drop++;
		}

		// Update statistics 
		dev->stats.rx_bytes += len;
		dev->stats.rx_packets++;
	}

	return num;
}*/

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
