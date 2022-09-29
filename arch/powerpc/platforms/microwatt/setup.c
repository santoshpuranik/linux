/*
 * Microwatt FPGA-based SoC platform setup code.
 *
 * Copyright 2020 Paul Mackerras (paulus@ozlabs.org), IBM Corp.
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>

#include <asm/machdep.h>
#include <asm/time.h>
#include <asm/xics.h>
#include <asm/udbg.h>

#define SYSCON_CTRL 0x28
#define SYSCON_CTRL_DRAM_AT_0	BIT(0)
#define SYSCON_CTRL_CORE_RESET	BIT(1)
#define SYSCON_CTRL_SOC_RESET	BIT(2)

static __iomem void *syscon_base;

static void __init microwatt_init_IRQ(void)
{
	xics_init();
}

static void __noreturn microwatt_restart(char *cmd)
{
	if (syscon_base) {
		u32 v = readl(syscon_base + SYSCON_CTRL);
		writel(v | SYSCON_CTRL_SOC_RESET, syscon_base + SYSCON_CTRL);
	}
	for (;;)
		;
}

static int __init microwatt_probe(void)
{
	return of_machine_is_compatible("microwatt-soc");
}

static int __init microwatt_populate(void)
{
	struct device_node *np;

	np = of_find_compatible_node(NULL, NULL, "microwatt,syscon");
	if (np) {
		syscon_base = of_iomap(np, 0);
		of_node_put(np);
	}

	return of_platform_default_populate(NULL, NULL, NULL);
}
machine_arch_initcall(microwatt, microwatt_populate);

define_machine(microwatt) {
	.name			= "microwatt",
	.probe			= microwatt_probe,
	.init_IRQ		= microwatt_init_IRQ,
	.progress		= udbg_progress,
	.calibrate_decr		= generic_calibrate_decr,
	.restart		= microwatt_restart,
};
