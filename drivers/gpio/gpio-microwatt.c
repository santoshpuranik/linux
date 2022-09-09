// SPDX-License-Identifier: GPL
#include <linux/platform_device.h>
#include <linux/gpio/driver.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/regmap.h>

#define MICROWATT_GPIO_DATA_OUT  0x00
#define MICROWATT_GPIO_DATA_IN   0x04
/* 1 = output, 0 = input */
#define MICROWATT_GPIO_DIR       0x08
#define MICROWATT_GPIO_DATA_SET  0x10
#define MICROWATT_GPIO_DATA_CLR  0x14
/* read for status, write 1 to clear */
#define MICROWATT_GPIO_INTR_ST   0x20
#define MICROWATT_GPIO_INTR_EN   0x24
/*
 TRIG0 TRIG1 TRIG2
 001 edge rising
 010 edge falling
 011 edge either
 100 level low
 101 level high
 */
#define MICROWATT_GPIO_INTR_TRIG0 0x28
#define MICROWATT_GPIO_INTR_TRIG1 0x2c
#define MICROWATT_GPIO_INTR_TRIG2 0x30

struct mw_gpio {
	struct gpio_chip chip;
	void __iomem *base;
	struct regmap *regs;
	unsigned int irq;
};

static int mw_gpio_irq_set_type(struct irq_data *data, unsigned int flow_type)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct mw_gpio *mw_gpio = gpiochip_get_data(chip);
	u32 offset = irqd_to_hwirq(data);
	unsigned long flags;
	u32 trig0, trig1, trig2;

	switch (flow_type) {
		case IRQ_TYPE_EDGE_BOTH:
			trig0 = 0;
			trig1 = 1;
			trig2 = 1;
			break;
		case IRQ_TYPE_EDGE_RISING:
			trig0 = 0;
			trig1 = 0;
			trig2 = 1;
			break;
		case IRQ_TYPE_EDGE_FALLING:
			trig0 = 0;
			trig1 = 1;
			trig2 = 0;
			break;
		case IRQ_TYPE_LEVEL_LOW:
			trig0 = 1;
			trig1 = 0;
			trig2 = 0;
			break;
		case IRQ_TYPE_LEVEL_HIGH:
			trig0 = 1;
			trig1 = 0;
			trig2 = 0;
			break;
		default:
			return -EINVAL;
	}

	switch (flow_type) {
		case IRQ_TYPE_EDGE_BOTH:
		case IRQ_TYPE_EDGE_RISING:
		case IRQ_TYPE_EDGE_FALLING:
			irq_set_handler_locked(data, handle_edge_irq);
			break;
		default:
			irq_set_handler_locked(data, handle_level_irq);
	}

	raw_spin_lock_irqsave(&chip->bgpio_lock, flags);
	/* disable while adjusting interrupts */
	regmap_update_bits(mw_gpio->regs, MICROWATT_GPIO_INTR_EN,
		BIT(offset), 0);
	regmap_update_bits(mw_gpio->regs, MICROWATT_GPIO_INTR_TRIG0,
		BIT(offset), trig0 << offset);
	regmap_update_bits(mw_gpio->regs, MICROWATT_GPIO_INTR_TRIG1,
		BIT(offset), trig1 << offset);
	regmap_update_bits(mw_gpio->regs, MICROWATT_GPIO_INTR_TRIG2,
		BIT(offset), trig2 << offset);
	regmap_update_bits(mw_gpio->regs, MICROWATT_GPIO_INTR_EN,
		BIT(offset), BIT(offset));
	raw_spin_unlock_irqrestore(&chip->bgpio_lock, flags);

	return 0;
}

static void mw_gpio_irq_mask(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct mw_gpio *mw_gpio = gpiochip_get_data(chip);
	u32 offset = irqd_to_hwirq(data);
	unsigned long flags;

	raw_spin_lock_irqsave(&chip->bgpio_lock, flags);
	regmap_update_bits(mw_gpio->regs, MICROWATT_GPIO_INTR_ST,
		BIT(offset), 0);
	raw_spin_unlock_irqrestore(&chip->bgpio_lock, flags);
}

static void mw_gpio_irq_unmask(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct mw_gpio *mw_gpio = gpiochip_get_data(chip);
	u32 offset = irqd_to_hwirq(data);
	unsigned long flags;

	raw_spin_lock_irqsave(&chip->bgpio_lock, flags);
	regmap_update_bits(mw_gpio->regs, MICROWATT_GPIO_INTR_ST,
		BIT(offset), 0xffffffff);
	raw_spin_unlock_irqrestore(&chip->bgpio_lock, flags);
}

static void mw_gpio_irq_ack(struct irq_data *data) 
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct mw_gpio *mw_gpio = gpiochip_get_data(chip);
	u32 offset = irqd_to_hwirq(data);

	regmap_write(mw_gpio->regs, MICROWATT_GPIO_INTR_ST, BIT(offset));
}

static void mw_gpio_irq_handler(struct irq_desc *desc)
{
	struct gpio_chip *chip = irq_desc_get_handler_data(desc);
	struct mw_gpio *mw_gpio = gpiochip_get_data(chip);
	struct irq_chip *irq_chip = irq_desc_get_chip(desc);
	unsigned int st1 = 0, n;
	unsigned long st2;

	chained_irq_enter(irq_chip, desc);
	regmap_read(mw_gpio->regs, MICROWATT_GPIO_INTR_ST, &st1);
	st2 = st1;
	for_each_set_bit(n, &st2, mw_gpio->chip.ngpio)
		generic_handle_domain_irq(chip->irq.domain, n);

	chained_irq_exit(irq_chip, desc);
}

static const struct regmap_config mw_gpio_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.disable_locking = true,
};

static const struct irq_chip mw_gpio_irq_chip = {
	.name		= "microwatt_gpio_irq",
	.irq_ack	= mw_gpio_irq_ack,
	.irq_mask	= mw_gpio_irq_mask,
	.irq_unmask	= mw_gpio_irq_unmask,
	.irq_set_type	= mw_gpio_irq_set_type,
	.flags		= IRQCHIP_IMMUTABLE,
	/* Provide the gpio resource callbacks */
	GPIOCHIP_IRQ_RESOURCE_HELPERS,
};

static int mw_gpio_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mw_gpio *mw_gpio = NULL;
	u32 ngpios;
	int rc;

	mw_gpio = devm_kzalloc(dev, sizeof(*mw_gpio), GFP_KERNEL);
	if (!mw_gpio)
		return -ENOMEM;

	rc = device_property_read_u32(dev, "ngpios", &ngpios);
	if (rc < 0)
		return rc;
	if (ngpios > 32) {
		dev_err(dev, "max ngpios is 32\n");
		return -EINVAL;
	}

	mw_gpio->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(mw_gpio->base))
		return PTR_ERR(mw_gpio->base);

	mw_gpio->regs = devm_regmap_init_mmio(dev, mw_gpio->base,
					   &mw_gpio_regmap_config);
	if (IS_ERR(mw_gpio->regs))
		return PTR_ERR(mw_gpio->regs);

	rc = bgpio_init(&mw_gpio->chip, dev, 4,
			mw_gpio->base + MICROWATT_GPIO_DATA_IN,
			mw_gpio->base + MICROWATT_GPIO_DATA_SET,
			mw_gpio->base + MICROWATT_GPIO_DATA_CLR,
			mw_gpio->base + MICROWATT_GPIO_DIR,
			NULL,
			0);
	if (rc) {
		dev_err(dev, "microwatt bgpio_init failed: %d\n", rc);
		return rc;
	}

	mw_gpio->chip.label = dev_name(dev);
	mw_gpio->chip.ngpio = ngpios;
	mw_gpio->chip.base = -1;
	mw_gpio->chip.parent = dev;
	mw_gpio->chip.of_node = pdev->dev.of_node;
	mw_gpio->chip.owner = THIS_MODULE;

	rc = platform_get_irq(pdev, 0);
	if (rc > 0) {
		struct gpio_irq_chip *girq = &mw_gpio->chip.irq;
		mw_gpio->irq = rc;
		gpio_irq_chip_set_chip(girq, &mw_gpio_irq_chip);
		girq->handler = handle_bad_irq;
		girq->parent_handler = mw_gpio_irq_handler;
		girq->num_parents = 1;
		girq->parents = &mw_gpio->irq;
	} else {
		dev_warn(dev, "TODO: missing interrupt\n");
	}

	rc = devm_gpiochip_add_data(&pdev->dev, &mw_gpio->chip, mw_gpio);
	if (rc < 0)
		return rc;

	return 0;
}

static const struct of_device_id mw_gpio_of_match[] = {
	{ .compatible = "openpower,microwatt-gpio", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, mw_gpio_of_match);

static struct platform_driver mw_gpio_driver = {
	.probe = mw_gpio_probe,
	// TODO: remove
	.driver = {
		.name = "microwatt-gpio",
		.of_match_table	= mw_gpio_of_match,
	},
};

module_platform_driver_probe(mw_gpio_driver, mw_gpio_probe);

MODULE_DESCRIPTION("Microwatt GPIO driver");
MODULE_AUTHOR("Matt Johnston <matt@codeconstruct.com.au>");
MODULE_LICENSE("GPL");
