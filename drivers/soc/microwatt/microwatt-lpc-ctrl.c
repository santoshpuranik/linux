// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Based on the microwatt-lpc-ctrl driver
 *
 * Copyright 2022 Antmicro
 */

#include <linux/log2.h>
#include <linux/mfd/syscon.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/poll.h>

#include <linux/aspeed-lpc-ctrl.h>

#define DEVICE_NAME	"microwatt-lpc-ctrl"

#define BASE_LO 0x00
#define BASE_HI 0x04
#define MASK_LO 0x08
#define MASK_HI 0x0c


struct microwatt_lpc_ctrl {
	struct miscdevice	miscdev;
	void __iomem		*base;
	phys_addr_t		mem_base;
	resource_size_t		mem_size;
};

static struct microwatt_lpc_ctrl *file_microwatt_lpc_ctrl(struct file *file)
{
	return container_of(file->private_data, struct microwatt_lpc_ctrl,
			miscdev);
}

static int microwatt_lpc_ctrl_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct microwatt_lpc_ctrl *lpc_ctrl = file_microwatt_lpc_ctrl(file);
	unsigned long vsize = vma->vm_end - vma->vm_start;
	pgprot_t prot = vma->vm_page_prot;

	if (vma->vm_pgoff + vma_pages(vma) > lpc_ctrl->mem_size >> PAGE_SHIFT)
		return -EINVAL;

	/* XXX: assuming accesses are not cache coherent */
	prot = pgprot_noncached(prot);

	if (remap_pfn_range(vma, vma->vm_start,
		(lpc_ctrl->mem_base >> PAGE_SHIFT) + vma->vm_pgoff,
		vsize, prot))
		return -EAGAIN;

	return 0;
}

static long microwatt_lpc_ctrl_ioctl(struct file *file, unsigned int cmd,
		unsigned long param)
{
	struct microwatt_lpc_ctrl *lpc_ctrl = file_microwatt_lpc_ctrl(file);
	struct device *dev = file->private_data;
	void __user *p = (void __user *)param;
	struct aspeed_lpc_ctrl_mapping map;
	u32 addr;
	u32 size;

	if (copy_from_user(&map, p, sizeof(map)))
		return -EFAULT;

	if (map.flags != 0)
		return -EINVAL;

	switch (cmd) {
	case ASPEED_LPC_CTRL_IOCTL_GET_SIZE:

		/* Support more than one window id in the future */
		if (map.window_id != 0)
			return -EINVAL;

		/* If memory-region is not described in device tree */
		if (!lpc_ctrl->mem_size) {
			dev_dbg(dev, "Didn't find reserved memory\n");
			return -ENXIO;
		}

		map.size = lpc_ctrl->mem_size;

		return copy_to_user(p, &map, sizeof(map)) ? -EFAULT : 0;
	case ASPEED_LPC_CTRL_IOCTL_MAP:

		if (!lpc_ctrl->mem_size) {
			dev_dbg(dev, "Didn't find reserved memory\n");
			return -ENXIO;
		}

		addr = lpc_ctrl->mem_base;
		size = lpc_ctrl->mem_size;

		/* Check overflow first! */
		if (map.offset + map.size < map.offset ||
			map.offset + map.size > size)
			return -EINVAL;

		if (map.size == 0 || map.size > size)
			return -EINVAL;

		addr += map.offset;

		writel(addr, lpc_ctrl->base + BASE_LO);
		writel(map.size - 1, lpc_ctrl->base + MASK_LO);

		return 0;
	}

	return -EINVAL;
}

static const struct file_operations microwatt_lpc_ctrl_fops = {
	.owner		= THIS_MODULE,
	.mmap		= microwatt_lpc_ctrl_mmap,
	.unlocked_ioctl	= microwatt_lpc_ctrl_ioctl,
};

static int microwatt_lpc_ctrl_probe(struct platform_device *pdev)
{
	struct microwatt_lpc_ctrl *lpc_ctrl;
	struct device_node *node;
	struct resource resm;
	struct device *dev;
	int rc;

	dev = &pdev->dev;

	lpc_ctrl = devm_kzalloc(dev, sizeof(*lpc_ctrl), GFP_KERNEL);
	if (!lpc_ctrl)
		return -ENOMEM;

	dev_set_drvdata(&pdev->dev, lpc_ctrl);

	lpc_ctrl->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(lpc_ctrl->base))
		return PTR_ERR(lpc_ctrl->base);

	/* If memory-region is described in device tree then store */
	node = of_parse_phandle(dev->of_node, "memory-region", 0);
	if (!node) {
		dev_err(dev, "Didn't find reserved memory\n");
		return -ENODEV;
	} else {
		rc = of_address_to_resource(node, 0, &resm);
		of_node_put(node);
		if (rc) {
			dev_err(dev, "Couldn't address to resource for reserved memory\n");
			return -ENXIO;
		}

		lpc_ctrl->mem_size = resource_size(&resm);
		lpc_ctrl->mem_base = resm.start;

		if (!is_power_of_2(lpc_ctrl->mem_size)) {
			dev_err(dev, "Reserved memory size must be a power of 2, got %u\n",
			       (unsigned int)lpc_ctrl->mem_size);
			return -EINVAL;
		}

		if (!IS_ALIGNED(lpc_ctrl->mem_base, lpc_ctrl->mem_size)) {
			dev_err(dev, "Reserved memory must be naturally aligned for size %u\n",
			       (unsigned int)lpc_ctrl->mem_size);
			return -EINVAL;
		}
	}

	lpc_ctrl->miscdev.minor = MISC_DYNAMIC_MINOR;
	lpc_ctrl->miscdev.name = DEVICE_NAME;
	lpc_ctrl->miscdev.fops = &microwatt_lpc_ctrl_fops;
	lpc_ctrl->miscdev.parent = dev;
	rc = misc_register(&lpc_ctrl->miscdev);
	if (rc) {
		dev_err(dev, "Unable to register device\n");
		return rc;
	}

	return 0;
}

static int microwatt_lpc_ctrl_remove(struct platform_device *pdev)
{
	struct microwatt_lpc_ctrl *lpc_ctrl = dev_get_drvdata(&pdev->dev);

	misc_deregister(&lpc_ctrl->miscdev);

	return 0;
}

static const struct of_device_id microwatt_lpc_ctrl_match[] = {
	{ .compatible = "ibm,microwatt-lpc-ctrl" },
	{ },
};

static struct platform_driver microwatt_lpc_ctrl_driver = {
	.driver = {
		.name		= DEVICE_NAME,
		.of_match_table = microwatt_lpc_ctrl_match,
	},
	.probe = microwatt_lpc_ctrl_probe,
	.remove = microwatt_lpc_ctrl_remove,
};

module_platform_driver(microwatt_lpc_ctrl_driver);

MODULE_DEVICE_TABLE(of, microwatt_lpc_ctrl_match);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maciej Sobkowski <msobkowski@antmicro.com>");
MODULE_DESCRIPTION("Control for Microwatt LPC HOST to BMC mappings");
