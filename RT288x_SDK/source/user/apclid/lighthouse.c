#include "apclid.h"
#include "api.h"
#include "ugw.h"

//gpio, on, off, blinks, rests, times.
static int lighthouse_led_gpio = 0;

//outdoor
//powr mask
static int odr_led_map[4] = {9, 14, 11, 12};
static void odr_init_led(void)
{
	int txpwr = 100, on = 0, off = 100, i;
	char *tmp = nvram_ra_get("TxPower");

	if(tmp && strlen(tmp)>0) {
		txpwr = atoi(tmp);
	}
	logdbg("txpwr: %d\n", txpwr);

	txpwr = (txpwr * 4) / 100; //0,1,2,3,4,
	for(i=0; i<4; i++) {
		if(txpwr >= i) {
			//led on
			on = 100; off = 1;
		}else{
			//led off
			on = 0; off = 100;
		}
		gpio_set_led(odr_led_map[i], on, off,
			ra_gpio_led_infinity, 0, 0);
	}

}

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

int lighthouse_init(void)
{
	char *gpio_led = nvram_ra_get("GpioLed");
	if(gpio_led && strlen(gpio_led)>0) {
		lighthouse_led_gpio = atoi(gpio_led);
	}

	logdbg("led gpio: %d\n", lighthouse_led_gpio);
	return 0;
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

static void usage() 
{
	fprintf(stderr, "lighthouse\n"
		"lighthouse led pin\n"
		"lighthouse reset pin\n");
}

int lighthouse_main(int argc, char *argv[])
{
	if(argc<2){
		logdbg("start reset pin handler...\n");
		return reset_handler();
	}

	if(strcmp(argv[1], "led") == 0) {
		lighthouse_led_gpio = atoi(argv[2]);
	}else if(strcmp(argv[1], "reset") == 0) {
		odr_init_led();
	}else{
		usage();
	}

	return 0;
}