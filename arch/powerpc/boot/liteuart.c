#include <stdint.h>
#include <stdbool.h>

#include "io.h"
#include "ops.h"
#include "of.h"
#include "stdio.h"

static void *uart_base;

/* From Linux liteuart.c */
#define OFF_RXTX	0x00
#define OFF_TXFULL	0x04
#define OFF_RXEMPTY	0x08
#define OFF_EV_STATUS	0x0c
#define OFF_EV_PENDING	0x10
#define OFF_EV_ENABLE	0x14

/* From litex uart.h */
#define UART_EV_TX	0x1
#define UART_EV_RX	0x2

/* Modified version of csr.h */
/* uart */
static inline uint32_t uart_rxtx_read(void) {
	return in_8(uart_base + OFF_RXTX);
}

static inline void uart_rxtx_write(uint32_t v) {
	out_8(uart_base + OFF_RXTX, v);
}

static inline uint32_t uart_txfull_read(void) {
	return in_8(uart_base + OFF_TXFULL);
}

static inline uint32_t uart_rxempty_read(void) {
	return in_8(uart_base + OFF_RXEMPTY);
}

static inline uint32_t uart_ev_status_read(void) {
	return in_8(uart_base + OFF_EV_STATUS);
}

static inline uint32_t uart_ev_pending_read(void) {
	return in_8(uart_base + OFF_EV_PENDING);
}
static inline void uart_ev_pending_write(uint32_t v) {
	out_8(uart_base + OFF_EV_PENDING, v);
}

static inline void uart_ev_enable_write(uint32_t v) {
	out_8(uart_base + OFF_EV_ENABLE, v);
}

// end of csr code

static char uart_read(void)
{
	char c;
	while (uart_rxempty_read());
	c = uart_rxtx_read();
	uart_ev_pending_write(UART_EV_RX);
	return c;
}

static int uart_read_nonblock(void)
{
	return (uart_rxempty_read() == 0);
}

static void uart_write(char c)
{
	while (uart_txfull_read());
	uart_rxtx_write(c);
	uart_ev_pending_write(UART_EV_TX);
}

static int uart_init(void)
{
	uart_ev_pending_write(uart_ev_pending_read());
	uart_ev_enable_write(UART_EV_TX | UART_EV_RX);
	return 0;
}

// static void uart_sync(void)
// {
// 	while (uart_txfull_read());
// }

static unsigned char liteuart_getchar(void)
{
	return uart_read();
}

static u8 liteuart_havechar(void)
{
	return uart_read_nonblock();
}

static void liteuart_putchar(unsigned char c)
{
	uart_write(c);
}

// static int liteuart_puts(const char *str)
// {
// 	unsigned int i;

// 	for (i = 0; *str; i++) {
// 		char c = *(str++);
// 		if (c == 10)
// 			liteuart_putchar(13);
// 		liteuart_putchar(c);
// 	}
// 	return 0;
// }

int liteuart_console_init(void *devp, struct serial_console_data *scdp)
{
	int n;
	u32 reg_offset;

	if (dt_get_virtual_reg(devp, (void **)&uart_base, 1) < 1) {
		printf("virt reg parse fail...\r\n");
		return -1;
	}

	n = getprop(devp, "reg-offset", &reg_offset, sizeof(reg_offset));
	if (n == sizeof(reg_offset))
		uart_base += be32_to_cpu(reg_offset);

	scdp->open = uart_init;
	scdp->putc = liteuart_putchar;
	scdp->getc = liteuart_getchar;
	scdp->tstc = liteuart_havechar;
	scdp->close = NULL;
	return 0;

}

