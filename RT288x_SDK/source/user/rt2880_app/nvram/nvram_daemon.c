#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <errno.h>
#include <linux/autoconf.h>

#include "nvram.h"
#include "flash_api.h"

#if defined (CONFIG_RALINK_GPIO) || defined (CONFIG_RALINK_GPIO_MODULE)
#include "ralink_gpio.h"
#define GPIO_DEV "/dev/gpio"
#endif

static char *saved_pidfile;

#define FC_MAX_DISP_VER 32
struct ConstFactorySt {
	char ac_ipaddr_def[64];
	char ac_ipaddr_port[16];
	char cloud_account[64];
	char cloud_password[64];
	char nick_name[128];
	char GpioLed[4];
	char *disp_version[FC_MAX_DISP_VER];
};

static struct ConstFactorySt cFactorys[] = {
	{
		ac_ipaddr_def:	"yun.sohowifi.cn",
		ac_ipaddr_port:	"8081",
		cloud_account: "",
		cloud_password: "cloud@leguang",
		nick_name: "Cloud AP",
		GpioLed: "0",
		disp_version: {"SYAP21", "SYAP23", "SYAP27", "SYAP28", "ODAP27", NULL},
	},{
		ac_ipaddr_def:	"yun.wangjie.com",
		ac_ipaddr_port:	"8081",
		cloud_account: "",
		cloud_password: "cloud@wangjie",
		nick_name: "X3",
		GpioLed: "9",
		disp_version: {"X3", NULL,},
	},{
		ac_ipaddr_def:	"yun.i-wiwi.com",
		ac_ipaddr_port:	"8081",
		cloud_account: "",
		cloud_password: "cloud@i-wiwi",
		nick_name: "CA",
		GpioLed: "0",
		disp_version: {"U298", NULL,},
	},
};

#define FC_NUM_FACTORYS (sizeof(cFactorys)/sizeof(struct ConstFactorySt))

void FixupFactoryInfo(void)
{
	char fidx, vidx = -1;
	char buff[32], *pstr;

	if(mtdpart_read("Factory", &fidx, 0x110, 1)<0) {
		logerr("mtd read failed.\n");
		return;
	}
	mtdpart_read("Factory", &vidx, 0x112, 1);

	if(fidx<0 || fidx>=FC_NUM_FACTORYS) {
		logerr("read factory init conf overflow %d.\n", fidx);
		fidx = 0;
	}
	if(vidx<0 || vidx >= FC_MAX_DISP_VER) {
		logerr("undefined disp ver idx for fidx: %d\n", fidx);
		vidx = -1;
	}

	logdbg("fixup use factory fidx: %d, vidx: %d\n", fidx, vidx);
	//覆盖默认nvram配置.
	if (strlen(cFactorys[fidx].ac_ipaddr_def) > 0){
		nvram_bufset(RT2860_NVRAM, "ac_ipaddr_def", cFactorys[fidx].ac_ipaddr_def);
		logdbg("fixup ac_ipaddr_def [%s]\n", cFactorys[fidx].ac_ipaddr_def);
	}
	if (strlen(cFactorys[fidx].ac_ipaddr_port) > 0){
		nvram_bufset(RT2860_NVRAM, "ac_ipaddr_port", cFactorys[fidx].ac_ipaddr_port);
		logdbg("fixup ac_port [%s]\n", cFactorys[fidx].ac_ipaddr_port);
	}
	if (strlen(cFactorys[fidx].cloud_account) > 0){
		nvram_bufset(RT2860_NVRAM, "cloud_account", cFactorys[fidx].cloud_account);
		logdbg("fixup accout [%s]\n", cFactorys[fidx].cloud_account);
	}
	if (strlen(cFactorys[fidx].cloud_password) > 0){
		nvram_bufset(RT2860_NVRAM, "cloud_password", cFactorys[fidx].cloud_password);
		//logdbg("fixup password [%s]\n", cFactorys[fidx].cloud_password);
	}
	if (strlen(cFactorys[fidx].nick_name) > 0){
		nvram_bufset(RT2860_NVRAM, "nick_name", cFactorys[fidx].nick_name);
		logdbg("fixup nick_name [%s]\n", cFactorys[fidx].nick_name);
	}
	if (strlen(cFactorys[fidx].GpioLed) > 0){
		nvram_bufset(RT2860_NVRAM, "GpioLed", cFactorys[fidx].GpioLed);
		logdbg("fixup GpioLed [%s]\n", cFactorys[fidx].GpioLed);
	}

	//fixup vidx
	if(vidx>=0) {
		snprintf(buff, sizeof(buff), "%s%s", 
			cFactorys[fidx].disp_version[vidx], strstr(UGW_VERSION, "-"));
	}else{
		snprintf(buff, sizeof(buff), "%s%s", HW_VERSION, strstr(UGW_VERSION, "-"));
	}
	nvram_bufset(RT2860_NVRAM, "os_version", buff);

	//fixup spec conf
	switch(fidx) {
		case 0:
		switch(vidx) {
			case 4:
				//OutDoor-xxx
				nvram_bufset(RT2860_NVRAM, "GpioLed", "9");
			break;
			default:
			break;
		}
		break;
		default:
		break;
	}
}

void loadDefault(void)
{
	nvram_close(RT2860_NVRAM);

	system("ralink_init clear 2860");
	system("ralink_init renew 2860 /etc_ro/Wireless/RT2860AP/RT2860_default_novlan");

    FixupFactoryInfo();
	nvram_close(RT2860_NVRAM);
}

/*
 * gpio interrupt handler -
 *   SIGUSR1 - notify goAhead to start WPS (by sending SIGUSR1)
 *   SIGUSR2 - restore default value
 */
static void nvramIrqHandler(int signum)
{
	if (signum == SIGUSR1) {
		int gopid;
		FILE *fp = fopen("/var/run/goahead.pid", "r");

		if (NULL == fp) {
			logerr("nvram: goAhead is not running\n");
			return;
		}
		fscanf(fp, "%d", &gopid);
		if (gopid < 2) {
			logerr("nvram: goAhead pid(%d) <= 1\n", gopid);
			return;
		}

		//send SIGUSR1 signal to goAhead for WPSPBCStart();
		logdbg("notify goahead to start WPS PBC..\n");
		kill(gopid, SIGUSR1);
		fclose(fp);
	} else if (signum == SIGUSR2) {
		logdbg("load default and reboot..\n");
		loadDefault();
		system("reboot -d 10");
	// } else if(signum == SIGTERM) {
	// 	logdbg("erase && close nvram & exit\n");
	// 	loadDefault();
	// 	closelog();
	// 	exit(EXIT_SUCCESS);
	} else {
		logdbg("sig: %d\n");
		return;
	}
}

/*
 * init gpio interrupt -
 *   1. config gpio interrupt mode
 *   2. register my pid and request gpio pin 0
 *   3. issue a handler to handle SIGUSR1 and SIGUSR2
 */
int initGpio(void)
{
	int fd;
	ralink_gpio_reg_info info;

	info.pid = getpid();
	info.irq = 1;	// MT7620 reset default

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
	//set gpio direction to input
	if (info.irq < 24) {
		if (ioctl(fd, RALINK_GPIO_SET_DIR_IN, (1<<info.irq)) < 0)
			goto ioctl_err;
	}
	//enable gpio interrupt
	if (ioctl(fd, RALINK_GPIO_ENABLE_INTP) < 0)
		goto ioctl_err;

	//register my information
	if (ioctl(fd, RALINK_GPIO_REG_IRQ, &info) < 0)
		goto ioctl_err;

	close(fd);

	//issue a handler to handle SIGUSR1 and SIGUSR2
	signal(SIGUSR1, nvramIrqHandler);
	signal(SIGUSR2, nvramIrqHandler);
	return 0;

ioctl_err:
	logerr("ioctl: %d\n", errno);
	close(fd);
	return -1;
}

static void pidfile_delete(void)
{
	if (saved_pidfile) unlink(saved_pidfile);
}

int pidfile_acquire(const char *pidfile)
{
	int pid_fd;
	if (!pidfile) return -1;

	pid_fd = open(pidfile, O_CREAT | O_WRONLY, 0644);
	if (pid_fd < 0) {
		logerr("Unable to open pidfile %s\n", pidfile);
	} else {
		lockf(pid_fd, F_LOCK, 0);
		if (!saved_pidfile)
			atexit(pidfile_delete);
		saved_pidfile = (char *) pidfile;
	}
	return pid_fd;
}

void pidfile_write_release(int pid_fd)
{
	FILE *out;

	if (pid_fd < 0) return;

	if ((out = fdopen(pid_fd, "w")) != NULL) {
		fprintf(out, "%d\n", getpid());
		fclose(out);
	}
	lockf(pid_fd, F_UNLCK, 0);
	close(pid_fd);
}

int main(int argc,char **argv)
{
	pid_t pid;
	int fd;

	openlog("nvdaemon", 0, 0);

	if (strcmp(nvram_bufget(RT2860_NVRAM, "WebInit"),"1")) {
		loadDefault();
	}
	//每次都强制写入版本信息, 防止被修改. 
	nvram_bufset(RT2860_NVRAM, "ugw_version", UGW_VERSION);
	//提交,关闭.
	nvram_close(RT2860_NVRAM);

	if (initGpio() != 0)
		exit(EXIT_FAILURE);

	fd = pidfile_acquire("/var/run/nvramd.pid");
	pidfile_write_release(fd);

	while (1) {
		pause();
	}

	closelog();

	exit(EXIT_SUCCESS);
}

