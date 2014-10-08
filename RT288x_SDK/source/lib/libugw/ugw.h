#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>

/********************/
/*		GPIO 		*/
/********************/
#include <linux/autoconf.h>

#define GPIO_DEV	"/dev/gpio"

enum {
	gpio_in,
	gpio_out,
};
enum {
#if defined (CONFIG_RALINK_RT3052)
	gpio2300,
	gpio3924,
	gpio5140,
#elif defined (CONFIG_RALINK_RT3883)
	gpio2300,
	gpio3924,
	gpio7140,
	gpio9572,
#elif defined (CONFIG_RALINK_RT3352)
	gpio2300,
	gpio3924,
	gpio4540,
#elif defined (CONFIG_RALINK_RT5350)
	gpio2100,
	gpio2722,
#elif defined (CONFIG_RALINK_RT6855A)
	gpio1500,
	gpio3116,
#elif defined (CONFIG_RALINK_MT7620)
	gpio2300,
	gpio3924,
	gpio7140,
	gpio72,
#elif defined (CONFIG_RALINK_MT7621)
	gpio3100,
	gpio6332,
	gpio9564,
#else
	gpio2300,
#endif
};

int gpio_set_dir(int r, int dir);
int gpio_read_int(int r, int *value);
int gpio_write_int(int r, int value);
int gpio_enb_irq(void);
int gpio_dis_irq(void);
int gpio_reg_info(int gpio_num);
int gpio_init(int dir);
int gpio_set_led(int gpio, int on, int off, int blinks, int resets, int times);
extern int ra_gpio_led_infinity;
