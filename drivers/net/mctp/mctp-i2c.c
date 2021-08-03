// SPDX-License-Identifier: GPL-2.0
/*
 * Management Controller Transport Protocol (MCTP)
 *
 * Copyright (c) 2021 Code Construct
 * Copyright (c) 2021 Google
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/i2c.h>
#include <linux/i2c-mux.h>
#include <linux/if_arp.h>
#include <net/mctp.h>

/* SMBus 3.0 allows 255 data bytes (plus PEC), but the
 * first byte is taken for source slave address.
 */
#define MCTP_I2C_MAXBLOCK 255
#define MCTP_I2C_MAXMTU (MCTP_I2C_MAXBLOCK - 1)
#define MCTP_I2C_MINMTU (64 + 4)
/* Allow space for address, command, byte_count, databytes, PEC */
#define MCTP_I2C_RXBUFSZ (3 + MCTP_I2C_MAXBLOCK + 1)
#define MCTP_I2C_MINLEN 8
#define MCTP_I2C_COMMANDCODE 0x0f
#define MCTP_I2C_TX_WORK_LEN 100
// sufficient for 64kB at min mtu
#define MCTP_I2C_TX_QUEUE_LEN 1100

#define MCTP_I2C_OF_PROP "mctp-controller"

struct mctp_i2c_hdr {
	u8 dest_slave;
	u8 command;
	u8 byte_count;
	u8 source_slave;
};

struct mctp_i2c_client;

// netdev and i2c transmit
struct mctp_i2c_dev {
	struct net_device *ndev;
	struct i2c_adapter *adapter;
	struct mctp_i2c_client *client;

	size_t pos;
	u8 buffer[MCTP_I2C_RXBUFSZ];

	struct workqueue_struct *tx_wq;
	struct work_struct tx_work;
	struct sk_buff_head tx_queue;
};

// i2c slave side for i2c receive
struct mctp_i2c_client {
	// client for a hardware i2c bus
	struct i2c_client *client;
	u8 lladdr;

	struct mctp_i2c_dev *dev;
};

static int mctp_i2c_recv(struct mctp_i2c_dev *midev);
static int mctp_i2c_slave_cb(struct i2c_client *client,
			     enum i2c_slave_event event, u8 *val);

/* Determines whether a device is an i2c adapter with
   the "mctp-controller" devicetree property set.
   Optionally returns the root i2c_adapter */
static struct i2c_adapter *mctp_i2c_adapter_match(struct device *dev,
	struct i2c_adapter **ret_root)
{
	struct i2c_adapter *root = NULL, *adap = NULL;

	if (dev->type != &i2c_adapter_type)
		return NULL;
	if (!dev->of_node)
		return NULL;
	if (!of_property_read_bool(dev->of_node, MCTP_I2C_OF_PROP))
		return NULL;
	root = i2c_root_adapter(dev);
	WARN_ONCE(!root, "%s failed to find root adapter for %pOF\n",
		__func__, dev->of_node);
	if (!root)
		return NULL;
	adap = to_i2c_adapter(dev);
	if (ret_root)
		*ret_root = root;
	return adap;
}

/* Creates a new i2c slave device attached to the root adapter.
 * Sets up the slave callback.
 * Must be called with a client on a root adapter.
 */
static struct mctp_i2c_client *mctp_i2c_new_client(struct i2c_client *client)
{
	struct mctp_i2c_client *mcli = NULL;
	struct i2c_adapter *root = NULL;
	int rc;

	if (client->flags & I2C_CLIENT_TEN) {
		dev_err(&client->dev, "failed, MCTP requires a 7-bit I2C address, addr=0x%x\n",
			client->addr);
		rc = -EINVAL;
		goto err;
	}

	root = i2c_root_adapter(&client->dev);
	if (!root) {
		dev_err(&client->dev, "failed to find root adapter\n");
		rc = -ENOENT;
		goto err;
	}
	if (root != client->adapter) {
		dev_err(&client->dev,
			"The mctp-i2c driver cannot be attached to an I2C mux adapter.\n"
			" The driver should be attached to the mux tree root adapter\n");
		rc = -EINVAL;
		goto err;
	}

	mcli = kzalloc(sizeof(*mcli), GFP_KERNEL);
	if (!mcli) {
		rc = -ENOMEM;
		goto err;
	}
	mcli->lladdr = client->addr & 0xff;
	mcli->client = client;
	i2c_set_clientdata(client, mcli);

	rc = i2c_slave_register(mcli->client, mctp_i2c_slave_cb);
	if (rc) {
		dev_err(&client->dev, "%s i2c register failed %d\n", __func__, rc);
		mcli->client = NULL;
		i2c_set_clientdata(client, NULL);
		goto err;
	}

	return mcli;
err:
	if (mcli) {
		if (mcli->client)
			i2c_unregister_device(mcli->client);
		kfree(mcli);
	}
	return ERR_PTR(rc);
}

static void mctp_i2c_free_client(struct mctp_i2c_client *mcli)
{
	int rc;

	rc = i2c_slave_unregister(mcli->client);
	// leak if it fails, we can't propagate errors upwards
	if (rc)
		dev_err(&mcli->client->dev,
			"%s i2c unregister failed %d\n", __func__, rc);
	else
		kfree(mcli);
}

static int mctp_i2c_slave_cb(struct i2c_client *client,
			     enum i2c_slave_event event, u8 *val)
{
	struct mctp_i2c_client *mcli = i2c_get_clientdata(client);
	struct mctp_i2c_dev *midev = NULL;
	int rc = 0;

	midev = mcli->dev;
	if (!midev)
		return 0;

	switch (event) {
	case I2C_SLAVE_WRITE_RECEIVED:
		if (midev->pos < MCTP_I2C_RXBUFSZ) {
			midev->buffer[midev->pos] = *val;
			midev->pos++;
		} else {
			midev->ndev->stats.rx_over_errors++;
		}

		break;
	case I2C_SLAVE_WRITE_REQUESTED:
		/* dest_slave as first byte */
		midev->buffer[0] = mcli->lladdr << 1;
		midev->pos = 1;
		break;
	case I2C_SLAVE_STOP:
		rc = mctp_i2c_recv(midev);
		break;
	default:
		break;
	}

	return rc;
}

static int mctp_i2c_recv(struct mctp_i2c_dev *midev)
{
	struct net_device *ndev = midev->ndev;
	struct mctp_i2c_hdr *hdr;
	struct mctp_skb_cb *cb;
	struct sk_buff *skb;
	u8 pec, calc_pec;
	size_t recvlen;

	/* Last byte is PEC */
	if (midev->pos < MCTP_I2C_MINLEN + 1) {
		ndev->stats.rx_length_errors++;
		return -EINVAL;
	}
	recvlen = midev->pos - 1;

	hdr = (void *)midev->buffer;
	if (hdr->command != MCTP_I2C_COMMANDCODE) {
		ndev->stats.rx_dropped++;
		return -EINVAL;
	}

	pec = midev->buffer[midev->pos - 1];
	calc_pec = i2c_smbus_pec(0, midev->buffer, recvlen);
	if (pec != calc_pec) {
		ndev->stats.rx_crc_errors++;
		return -EINVAL;
	}

	skb = netdev_alloc_skb(ndev, recvlen);
	if (!skb) {
		ndev->stats.rx_dropped++;
		return -ENOMEM;
	}

	skb->protocol = htons(ETH_P_MCTP);
	skb_put_data(skb, midev->buffer, recvlen);
	skb_reset_mac_header(skb);
	skb_pull(skb, sizeof(struct mctp_i2c_hdr));
	skb_reset_network_header(skb);

	cb = __mctp_cb(skb);
	cb->halen = 1;
	cb->haddr[0] = hdr->source_slave;

	if (netif_receive_skb(skb) == NET_RX_SUCCESS) {
		ndev->stats.rx_packets++;
		ndev->stats.rx_bytes += skb->len;
	} else {
		ndev->stats.rx_dropped++;
	}
	return 0;
}

static void mctp_i2c_xmit(struct mctp_i2c_dev *midev, struct sk_buff *skb)
{
	// TODO: are we meant to use rtnl_link_stats64 instead of ->stats?
	struct net_device_stats *stats = &midev->ndev->stats;
	struct mctp_i2c_hdr *hdr;
	unsigned int len;
	u16 daddr;
	int rc;

	len = skb->len;
	hdr = (void *)skb_mac_header(skb);

	stats->tx_bytes += len;
	stats->tx_packets++;

	daddr = hdr->dest_slave >> 1;

	rc = i2c_smbus_xfer(midev->adapter, daddr, I2C_CLIENT_PEC,
			    I2C_SMBUS_WRITE, hdr->command, I2C_SMBUS_BLOCK_DATA,
		(void *)&hdr->byte_count);
	if (rc) {
		dev_dbg(&midev->adapter->dev, "%s i2c_smbus_xfer failed %d",
			__func__, rc);
		stats->tx_errors++;
	}
}

static int mctp_i2c_header_create(struct sk_buff *skb, struct net_device *dev,
				  unsigned short type, const void *daddr,
				  const void *saddr, unsigned int len)
{
	struct mctp_i2c_hdr *hdr;
	struct mctp_hdr *mhdr;
	u8 lldst, llsrc;

	lldst = *((u8 *)daddr);
	llsrc = *((u8 *)saddr);

	// TODO: check for broadcast daddr? other addr sanity checks?

	skb_push(skb, sizeof(struct mctp_i2c_hdr));
	skb_reset_mac_header(skb);
	hdr = (void *)skb_mac_header(skb);
	mhdr = mctp_hdr(skb);
	hdr->dest_slave = (lldst << 1) & 0xff;
	hdr->command = MCTP_I2C_COMMANDCODE;
	hdr->byte_count = len + 1;
	if (hdr->byte_count > MCTP_I2C_MAXBLOCK)
		return -EMSGSIZE;
	hdr->source_slave = ((llsrc << 1) & 0xff) | 0x01;
	mhdr->ver = 0x01;

	return 0;
}

static void mctp_i2c_tx_dowork(struct work_struct *ws)
{
	struct mctp_i2c_dev *midev = container_of(ws,
		struct mctp_i2c_dev, tx_work);
	struct sk_buff *skb;
	unsigned long flags;

	while (1) {
		spin_lock_irqsave(&midev->tx_queue.lock, flags);
		skb = __skb_dequeue(&midev->tx_queue);
		if (!skb) {
			spin_unlock_irqrestore(&midev->tx_queue.lock, flags);
			return;
		}

		if (netif_queue_stopped(midev->ndev))
			netif_wake_queue(midev->ndev);
		spin_unlock_irqrestore(&midev->tx_queue.lock, flags);

		mctp_i2c_xmit(midev, skb);
		kfree_skb(skb);
	}
}

static netdev_tx_t mctp_i2c_start_xmit(struct sk_buff *skb,
				       struct net_device *dev)
{
	struct mctp_i2c_dev *midev = netdev_priv(dev);
	unsigned long flags;

	spin_lock_irqsave(&midev->tx_queue.lock, flags);
	if (skb_queue_len(&midev->tx_queue) >= MCTP_I2C_TX_WORK_LEN) {
		netif_stop_queue(dev);
		spin_unlock_irqrestore(&midev->tx_queue.lock, flags);
		netdev_err(dev, "BUG! Tx Ring full when queue awake!\n");
		return NETDEV_TX_BUSY;
	}

	__skb_queue_tail(&midev->tx_queue, skb);
	if (skb_queue_len(&midev->tx_queue) == MCTP_I2C_TX_WORK_LEN)
		netif_stop_queue(dev);
	spin_unlock_irqrestore(&midev->tx_queue.lock, flags);
	queue_work(midev->tx_wq, &midev->tx_work);
	return NETDEV_TX_OK;
}

static const struct net_device_ops mctp_i2c_ops = {
	.ndo_start_xmit = mctp_i2c_start_xmit,
};

static const struct header_ops mctp_i2c_headops = {
	.create = mctp_i2c_header_create,
};

static void mctp_i2c_net_setup(struct net_device *dev)
{
	dev->type = ARPHRD_MCTP;

	dev->mtu = MCTP_I2C_MAXMTU;
	dev->min_mtu = MCTP_I2C_MINMTU;
	dev->max_mtu = MCTP_I2C_MAXMTU;
	dev->tx_queue_len = MCTP_I2C_TX_QUEUE_LEN;

	dev->hard_header_len = sizeof(struct mctp_i2c_hdr);
	dev->addr_len = 1;

	dev->netdev_ops		= &mctp_i2c_ops;
	dev->header_ops		= &mctp_i2c_headops;
	dev->needs_free_netdev  = true;
}

static int mctp_i2c_add_netdev(struct mctp_i2c_client *mcli,
			       struct i2c_adapter *adap)
{
	struct mctp_i2c_dev *midev = NULL;
	struct net_device *ndev = NULL;
	char namebuf[30];
	int rc;

	snprintf(namebuf, sizeof(namebuf), "mctpi2c%d", adap->nr);
	ndev = alloc_netdev(sizeof(*midev), namebuf, NET_NAME_ENUM, mctp_i2c_net_setup);
	if (!ndev) {
		rc = -ENOMEM;
		dev_err(&mcli->client->dev, "%s alloc netdev failed\n", __func__);
		goto err;
	}
	dev_net_set(ndev, current->nsproxy->net_ns);
	SET_NETDEV_DEV(ndev, &adap->dev);
	ndev->dev_addr = &mcli->lladdr;

	midev = netdev_priv(ndev);
	INIT_WORK(&midev->tx_work, mctp_i2c_tx_dowork);
	skb_queue_head_init(&midev->tx_queue);
	midev->adapter = adap;
	midev->client = mcli;
	/* Hold references */
	get_device(&midev->adapter->dev);
	get_device(&midev->client->client->dev);
	midev->ndev = ndev;
	midev->tx_wq = alloc_ordered_workqueue("%s_tx", WQ_FREEZABLE,
					       ndev->name);
	if (!midev->tx_wq) {
		rc = -ENOMEM;
		goto err;
	}

	rc = register_netdev(ndev);
	if (rc) {
		dev_err(&mcli->client->dev,
			"%s register netdev \"%s\" failed %d\n", __func__,
			ndev->name, rc);
		goto err;
	}
	mcli->dev = midev;

	return 0;
err:
	if (midev && midev->tx_wq)
		destroy_workqueue(midev->tx_wq);

	if (ndev)
		free_netdev(ndev);

	return rc;
}

static void mctp_i2c_free_netdev(struct mctp_i2c_dev *midev)
{
	struct mctp_i2c_client *mcli = midev->client;

	/* Flush TX to i2c */
	netif_stop_queue(midev->ndev);
	destroy_workqueue(midev->tx_wq);
	WARN_ON(!skb_queue_empty(&midev->tx_queue));

	/* Release references, used only for TX which has stopped */
	put_device(&midev->adapter->dev);
	put_device(&mcli->client->dev);

	/* Remove it from the parent mcli */
	mcli->dev = NULL;

	/* Remove netdev. mctp_i2c_slave_cb() takes a dev_hold() so removing
	 * it now is safe. unregister_netdev() frees ndev and midev.
	 */
	unregister_netdev(midev->ndev);
}

static int mctp_i2c_probe(struct i2c_client *client)
{
	struct mctp_i2c_client *mcli = NULL;
	int rc;

	/* Check for >32 byte block support required for MCTP */
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_SMBUS_V3_BLOCK)) {
		dev_err(&client->dev,
			"%s failed, I2C bus driver does not support 255 byte block transfer\n",
			__func__);
		return -EOPNOTSUPP;
	}

	if (client->adapter->dev.of_node &&
	    !mctp_i2c_adapter_match(&client->adapter->dev, NULL)) {
		dev_info(&client->dev,
			"Not attaching, %s property is not set on I2C adapter %s",
			MCTP_I2C_OF_PROP, dev_name(&client->adapter->dev));
		return -ENODEV;
	}

	mcli = mctp_i2c_new_client(client);
	if (IS_ERR(mcli)) {
		rc = PTR_ERR(mcli);
		mcli = NULL;
		goto err;
	}

	rc = mctp_i2c_add_netdev(mcli, client->adapter);
	if (rc < 0)
		goto err;

	return 0;
err:
	if (mcli)
		mctp_i2c_free_client(mcli);
	return rc;
}

static int mctp_i2c_remove(struct i2c_client *client)
{
	struct mctp_i2c_client *mcli = i2c_get_clientdata(client);

	mctp_i2c_free_netdev(mcli->dev);
	mctp_i2c_free_client(mcli);
	// Callers ignore return code
	return 0;
}

static const struct i2c_device_id mctp_i2c_id[] = {
	{ "mctp-i2c", 0 },
	{},
};
MODULE_DEVICE_TABLE(i2c, mctp_i2c_id);

static const struct of_device_id mctp_i2c_of_match[] = {
	{ .compatible = "mctp-i2c-controller" },
	{},
};
MODULE_DEVICE_TABLE(of, mctp_i2c_of_match);

static struct i2c_driver mctp_i2c_driver = {
	.driver = {
		.name = "mctp-i2c",
		.of_match_table = mctp_i2c_of_match,
	},
	.probe_new = mctp_i2c_probe,
	.remove = mctp_i2c_remove,
	.id_table = mctp_i2c_id,
};

static __init int mctp_i2c_init(void)
{
	int rc;

	pr_info("MCTP SMBus/I2C transport driver\n");
	rc = i2c_add_driver(&mctp_i2c_driver);
	if (rc)
		return rc;
	return 0;
}

static __exit void mctp_i2c_exit(void)
{
	i2c_del_driver(&mctp_i2c_driver);
}

module_init(mctp_i2c_init);
module_exit(mctp_i2c_exit);

MODULE_DESCRIPTION("MCTP SMBus/I2C device");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Matt Johnston <matt@codeconstruct.com.au>");
