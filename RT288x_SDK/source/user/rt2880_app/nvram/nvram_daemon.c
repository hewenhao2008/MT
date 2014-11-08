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

struct ConstFactorySt {
	char ac_ipaddr[64];
	char ac_ipaddr_port[16];
	char cloud_account[64];
	char cloud_password[64];
	char nick_name[128];
};

static struct ConstFactorySt cFactorys[] = {
	{
		ac_ipaddr:	"yun.sohowifi.cn",
		ac_ipaddr_port:	"8081",
		cloud_account: "leguang",
		cloud_password: "cloud@leguang",
		nick_name: "乐光",
	},{
		ac_ipaddr:	"yun.wangjie.com",
		ac_ipaddr_port:	"8081",
		cloud_account: "wangjie",
		cloud_password: "cloud@wangjie",
		nick_name: "网捷",
	},{
		ac_ipaddr:	"yun.i-wiwi.com",
		ac_ipaddr_port:	"8081",
		cloud_account: "shenlan",
		cloud_password: "cloud@i-wiwi",
		nick_name: "深蓝",
	},
};

enum {
	FC_LEGUANG = 0,
	FC_WANGJIE,
	FC_MAX_SUPPORTED,
};

#define NUM_FACTORYS (sizeof(cFactorys)/sizeof(struct ConstFactorySt))

void FixupFactoryInfo(void)
{
	char idx;

	if(mtdpart_read("Factory", &idx, 0x110, 1)<0) {
		logerr("mtd read failed.\n");
		return;
	}
	if(idx<0 || idx>=NUM_FACTORYS) {
		logerr("read factory init conf overflow %d.\n", idx);
		return;
	}

	logdbg("fixup use factory idx: %d\n", idx);
	//覆盖默认nvram配置.
	if (strlen(cFactorys[idx].ac_ipaddr) > 0){
		nvram_bufset(RT2860_NVRAM, "ac_ipaddr", cFactorys[idx].ac_ipaddr);
		logdbg("fixup ac_ipaddr [%s]\n", cFactorys[idx].ac_ipaddr);
	}
	if (strlen(cFactorys[idx].ac_ipaddr_port) > 0){
		nvram_bufset(RT2860_NVRAM, "ac_ipaddr_port", cFactorys[idx].ac_ipaddr_port);
		logdbg("fixup ac_port [%s]\n", cFactorys[idx].ac_ipaddr_port);
	}
	if (strlen(cFactorys[idx].cloud_account) > 0){
		nvram_bufset(RT2860_NVRAM, "cloud_account", cFactorys[idx].cloud_account);
		logdbg("fixup accout [%s]\n", cFactorys[idx].cloud_account);
	}
	if (strlen(cFactorys[idx].cloud_password) > 0){
		nvram_bufset(RT2860_NVRAM, "cloud_password", cFactorys[idx].cloud_password);
		//logdbg("fixup password [%s]\n", cFactorys[idx].cloud_password);
	}
	if (strlen(cFactorys[idx].nick_name) > 0){
		nvram_bufset(RT2860_NVRAM, "nick_name", cFactorys[idx].nick_name);
		logdbg("fixup nick_name [%s]\n", cFactorys[idx].nick_name);
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

