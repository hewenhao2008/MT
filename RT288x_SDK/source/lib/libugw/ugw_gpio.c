//ugw_gpio.c
#include "ugw.h"
#include "ralink_gpio.h"

int ra_gpio_led_infinity = RALINK_GPIO_LED_INFINITY;

int gpio_set_dir(int r, int dir)
{
	int fd, req;

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
	if (dir == gpio_in) {
#if defined (CONFIG_RALINK_RT3052)
		if (r == gpio5140)
			req = RALINK_GPIO5140_SET_DIR_IN;
		else if (r == gpio3924)
			req = RALINK_GPIO3924_SET_DIR_IN;
		else
#elif defined (CONFIG_RALINK_RT3883)
		if (r == gpio9572)
			req = RALINK_GPIO9572_SET_DIR_IN;
		else if (r == gpio7140)
			req = RALINK_GPIO7140_SET_DIR_IN;
		else if (r == gpio3924)
			req = RALINK_GPIO3924_SET_DIR_IN;
		else
#elif defined (CONFIG_RALINK_RT3352)
		if (r == gpio4540)
			req = RALINK_GPIO4540_SET_DIR_IN;
		else if (r == gpio3924)
			req = RALINK_GPIO3924_SET_DIR_IN;
		else
#elif defined (CONFIG_RALINK_RT5350)
		if (r == gpio2722)
			req = RALINK_GPIO2722_SET_DIR_IN;
		else
#elif defined (CONFIG_RALINK_RT6855A)
		if (r == gpio3116)
			req = RALINK_GPIO3116_SET_DIR_IN;
		else
#elif defined (CONFIG_RALINK_MT7620)
		if (r == gpio72)
			req = RALINK_GPIO72_SET_DIR_IN;
		else if (r == gpio7140)
			req = RALINK_GPIO7140_SET_DIR_IN;
		else if (r == gpio3924)
			req = RALINK_GPIO3924_SET_DIR_IN;
		else
#elif defined (CONFIG_RALINK_MT7621)
		if (r == gpio9564)
			req = RALINK_GPIO9564_SET_DIR_IN;
		else if (r == gpio6332)
			req = RALINK_GPIO6332_SET_DIR_IN;
		else
#endif
			req = RALINK_GPIO_SET_DIR_IN;
	}
	else {
#if defined (CONFIG_RALINK_RT3052)
		if (r == gpio5140)
			req = RALINK_GPIO5140_SET_DIR_OUT;
		else if (r == gpio3924)
			req = RALINK_GPIO3924_SET_DIR_OUT;
		else
#elif defined (CONFIG_RALINK_RT3883)
		if (r == gpio9572)
			req = RALINK_GPIO9572_SET_DIR_OUT;
		else if (r == gpio7140)
			req = RALINK_GPIO7140_SET_DIR_OUT;
		else if (r == gpio3924)
			req = RALINK_GPIO3924_SET_DIR_OUT;
#elif defined (CONFIG_RALINK_RT3352)
		if (r == gpio4540)
			req = RALINK_GPIO4540_SET_DIR_OUT;
		else if (r == gpio3924)
			req = RALINK_GPIO3924_SET_DIR_OUT;
		else
#elif defined (CONFIG_RALINK_RT5350)
		if (r == gpio2722)
			req = RALINK_GPIO2722_SET_DIR_OUT;
		else
#elif defined (CONFIG_RALINK_RT6855A)
		if (r == gpio3116)
			req = RALINK_GPIO3116_SET_DIR_OUT;
		else
#elif defined (CONFIG_RALINK_MT7620)
		if (r == gpio72)
			req = RALINK_GPIO72_SET_DIR_OUT;
		else if (r == gpio7140)
			req = RALINK_GPIO7140_SET_DIR_OUT;
		else if (r == gpio3924)
			req = RALINK_GPIO3924_SET_DIR_OUT;
#elif defined (CONFIG_RALINK_MT7621)
		if (r == gpio9564)
			req = RALINK_GPIO9564_SET_DIR_OUT;
		else if (r == gpio6332)
			req = RALINK_GPIO6332_SET_DIR_OUT;
		else
#endif
			req = RALINK_GPIO_SET_DIR_OUT;
	}
	if (ioctl(fd, req, 0xffffffff) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int gpio_read_int(int r, int *value)
{
	int fd, req;

	*value = 0;
	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}

#if defined (CONFIG_RALINK_RT3052)
	if (r == gpio5140)
		req = RALINK_GPIO5140_READ;
	else if (r == gpio3924)
		req = RALINK_GPIO3924_READ;
	else
#elif defined (CONFIG_RALINK_RT3883)
	if (r == gpio9572)
		req = RALINK_GPIO9572_READ;
	else if (r == gpio7140)
		req = RALINK_GPIO7140_READ;
	else if (r == gpio3924)
		req = RALINK_GPIO3924_READ;
	else
#elif defined (CONFIG_RALINK_RT3352)
	if (r == gpio4540)
		req = RALINK_GPIO4540_READ;
	else if (r == gpio3924)
		req = RALINK_GPIO3924_READ;
	else
#elif defined (CONFIG_RALINK_RT5350)
	if (r == gpio2722)
		req = RALINK_GPIO2722_READ;
	else
#elif defined (CONFIG_RALINK_MT7620)
	if (r == gpio72)
		req = RALINK_GPIO72_READ;
	else if (r == gpio7140)
		req = RALINK_GPIO7140_READ;
	else if (r == gpio3924)
		req = RALINK_GPIO3924_READ;
	else
#elif defined (CONFIG_RALINK_MT7621)
	if (r == gpio9564)
		req = RALINK_GPIO9564_READ;
	else if (r == gpio6332)
		req = RALINK_GPIO6332_READ;
	else
#endif
		req = RALINK_GPIO_READ;
	if (ioctl(fd, req, value) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int gpio_write_int(int r, int value)
{
	int fd, req;

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
#if defined (CONFIG_RALINK_RT3052)
	if (r == gpio5140)
		req = RALINK_GPIO5140_WRITE;
	else if (r == gpio3924)
		req = RALINK_GPIO3924_WRITE;
	else
#elif defined (CONFIG_RALINK_RT3883)
	if (r == gpio9572)
		req = RALINK_GPIO9572_WRITE;
	else if (r == gpio7140)
		req = RALINK_GPIO7140_WRITE;
	else if (r == gpio3924)
		req = RALINK_GPIO3924_WRITE;
	else
#elif defined (CONFIG_RALINK_RT3352)
	if (r == gpio4540)
		req = RALINK_GPIO4540_WRITE;
	else if (r == gpio3924)
		req = RALINK_GPIO3924_WRITE;
	else
#elif defined (CONFIG_RALINK_RT5350)
	if (r == gpio2722)
		req = RALINK_GPIO2722_WRITE;
	else
#elif defined (CONFIG_RALINK_MT7620)
	if (r == gpio72)
		req = RALINK_GPIO72_WRITE;
	else if (r == gpio7140)
		req = RALINK_GPIO7140_WRITE;
	else if (r == gpio3924)
		req = RALINK_GPIO3924_WRITE;
	else
#elif defined (CONFIG_RALINK_MT7621)
	if (r == gpio9564)
		req = RALINK_GPIO9564_WRITE;
	else if (r == gpio6332)
		req = RALINK_GPIO6332_WRITE;
	else
#endif
		req = RALINK_GPIO_WRITE;
	if (ioctl(fd, req, value) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int gpio_init(int dir)
{
	//set gpio direction to dir
#if defined (CONFIG_RALINK_RT3052)
	gpio_set_dir(gpio5140, dir);
	gpio_set_dir(gpio3924, dir);
	gpio_set_dir(gpio2300, dir);
#elif defined (CONFIG_RALINK_RT3352)
	gpio_set_dir(gpio4540, dir);
	gpio_set_dir(gpio3924, dir);
	gpio_set_dir(gpio2300, dir);
#elif defined (CONFIG_RALINK_RT3883)
	gpio_set_dir(gpio9572, dir);
	gpio_set_dir(gpio7140, dir);
	gpio_set_dir(gpio3924, dir);
	gpio_set_dir(gpio2300, dir);
#elif defined (CONFIG_RALINK_RT5350)
	gpio_set_dir(gpio2722, dir);
	gpio_set_dir(gpio2100, dir);
#elif defined (CONFIG_RALINK_RT6855A)
	gpio_set_dir(gpio3116, dir);
	gpio_set_dir(gpio1500, dir);
#elif defined (CONFIG_RALINK_MT7620)
	gpio_set_dir(gpio72, dir);
	gpio_set_dir(gpio7140, dir);
	gpio_set_dir(gpio3924, dir);
	gpio_set_dir(gpio2300, dir);
#elif defined (CONFIG_RALINK_MT7621)
	gpio_set_dir(gpio9564, dir);
	gpio_set_dir(gpio6332, dir);
	gpio_set_dir(gpio3100, dir);
#else
	gpio_set_dir(gpio2300, dir);
#endif
	return 0;
}

int gpio_enb_irq(void)
{
	int fd;

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
	if (ioctl(fd, RALINK_GPIO_ENABLE_INTP) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int gpio_dis_irq(void)
{
	int fd;

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
	if (ioctl(fd, RALINK_GPIO_DISABLE_INTP) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int gpio_reg_info(int gpio_num)
{
	int fd;
	ralink_gpio_reg_info info;

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
	info.pid = getpid();
	info.irq = gpio_num;
	if (ioctl(fd, RALINK_GPIO_REG_IRQ, &info) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int gpio_set_led(int gpio, int on, int off, int blinks, int resets, int times)
{
	int fd;
	ralink_gpio_led_info led;

	led.gpio = gpio;
	if (led.gpio < 0 || led.gpio >= RALINK_GPIO_NUMBER) {
		printf("gpio number %d out of range (should be 0 ~ %d)\n", led.gpio, RALINK_GPIO_NUMBER);
		return;
	}
	led.on = on;
	if (led.on > RALINK_GPIO_LED_INFINITY) {
		printf("on interval %d out of range (should be 0 ~ %d)\n", led.on, RALINK_GPIO_LED_INFINITY);
		return;
	}
	led.off = off;
	if (led.off > RALINK_GPIO_LED_INFINITY) {
		printf("off interval %d out of range (should be 0 ~ %d)\n", led.off, RALINK_GPIO_LED_INFINITY);
		return;
	}
	led.blinks = blinks;
	if (led.blinks > RALINK_GPIO_LED_INFINITY) {
		printf("number of blinking cycles %d out of range (should be 0 ~ %d)\n", led.blinks, RALINK_GPIO_LED_INFINITY);
		return;
	}
	led.rests = resets;
	if (led.rests > RALINK_GPIO_LED_INFINITY) {
		printf("number of resting cycles %d out of range (should be 0 ~ %d)\n", led.rests, RALINK_GPIO_LED_INFINITY);
		return;
	}
	led.times = times;
	if (led.times > RALINK_GPIO_LED_INFINITY) {
		printf("times of blinking %d out of range (should be 0 ~ %d)\n", led.times, RALINK_GPIO_LED_INFINITY);
		return;
	}

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return;
	}
	if (ioctl(fd, RALINK_GPIO_LED_SET, &led) < 0) {
		perror("ioctl");
		close(fd);
		return;
	}
	close(fd);
}