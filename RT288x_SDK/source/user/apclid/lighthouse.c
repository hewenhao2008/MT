#include "apclid.h"
#include "api.h"
#include "ugw.h"

//gpio, on, off, blinks, rests, times.
static int lighthouse_led_gpio = 0;

static void signal_handler(int signum)
{
	printf("gpio tester: signal ");
	if (signum == SIGUSR1)
		printf("SIGUSR1");
	else if (signum == SIGUSR2)
		printf("SIGUSR2");
	else
		printf("%d", signum);
	printf(" received\n", signum);
}

int lighthouse_set_ac_ok(void)
{
	return gpio_set_led(lighthouse_led_gpio, 5, 5, 
		ra_gpio_led_infinity, 0, 0);
}

int lighthouse_set_cloud_ok(void)
{
	return gpio_set_led(lighthouse_led_gpio, 30, 5, 
		ra_gpio_led_infinity, 0, 0);
}

int lighthouse_set_lose(void)
{
	return gpio_set_led(lighthouse_led_gpio, 1, 1, 
		ra_gpio_led_infinity, 0, 0);
}

static int reset_handler(void)
{
	//set gpio direction to input
	gpio_init(gpio_in);

	//enable gpio interrupt
	gpio_enb_irq();

	//register my information
	gpio_reg_info(0); //all pin

	//issue a handler to handle SIGUSR1
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);

	//wait for signal
	pause();

	//disable gpio interrupt
	gpio_dis_irq();
}

int lighthouse_main(int argc, char *argv[])
{
	if(argc<2){
		logdbg("start reset pin handler...\n");
		return reset_handler();
	}

	return 0;
}