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
	gpio2300,
	gpio3924,
	gpio7140,
	gpio72,
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

//LIB IO
ssize_t safe_read(int fd, void *buf, size_t count);
ssize_t safe_write(int fd, const void *buf, size_t count);
int safe_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
int safe_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int waitfor(int fd, int timeout);
