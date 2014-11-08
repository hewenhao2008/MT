#include "apclid.h"
#include "api.h"

//全局变量
int ac_addr_invalid = 0;
extern int wlconf_main(int argc, char *argv[]);
extern int press_any_key_main(int argc, char *argv[]);
extern int lighthouse_main(int argc, char *argv[]);

static void signal_handler(int sig)
{
	syslog(LOG_INFO, "apclid exiting sig:%d...\n", sig);
	closelog();

	//灯塔信号: 找到AC.
	lighthouse_set_lose();
	exit(0);
}


int main(char argc, char *argv[])
{
	int r;

	if(strstr(argv[0], "wlconf")!=NULL) {
		logdbg("start wlconf...\n");
		return wlconf_main(argc, argv);
	}

	if(strstr(argv[0], "press_any_key")!=NULL) {
		logdbg("start press_any_key...\n");
		return press_any_key_main(argc, argv);
	}

	if(strstr(argv[0], "lighthouse")!=NULL) {
		logdbg("start lighthouse ...\n");
		return lighthouse_main(argc, argv);
	}

	if(strstr(argv[0], "apclid")==NULL) {
		logerr("unknown par[%s]\n", argv[0]);
		return 0;
	}

	openlog("apclid", 0, 0);
	signal(SIGTERM, signal_handler);
	signal(SIGKILL, signal_handler);
	signal(SIGINT, signal_handler);

	if (argc>1 && strncmp(argv[1], "dbg", 3)==0) {
		//debug mode
	}else{
		if (daemon(1, 1) == -1) {
			logerr("daemon failed %d\n", errno);
			goto __err;
		}
	}

	init_handlers();
	lighthouse_init();

	logdbg("apclid starting...\n");

	ac_addr_invalid = 0;
	time_t start_ts = time(NULL);
	while(1) {
		//cleanup alert message
		nvram_ra_unset("ap_alert");
		nvram_ra_unset("ac_connected");

		//设置灯塔:丢失信号
		lighthouse_set_lose();

		//第一次, 等5min才转DHCP.
		int esp;
		do {
			//优先从配置读取ac地址.
			start_ap_client();
			//连接中断.
			lighthouse_set_lose();

			esp = (time(NULL)-start_ts);
			if(esp < 0) {
				//防止时间同步后, 越界.
				start_ts = time(NULL);
			}
			logerr("connect failed, try %d secs\n", esp);
		} while (esp < 60 && esp > 0);

		//超时, 连不上, 切换dhcp, 并且从广播获取AC地址.
		if (!nvram_ra_match("ap_standalone", "1") || (time(NULL) - start_ts >= 180)) {
			//5-10, min, not found ac. 
			ac_addr_invalid ++; //广播获取AC地址
			ac_addr_invalid %= 3; //每个N次, 再尝试配置地址, 防止一直连不上.

			//udhcpc -i br0 -p /var/run/udhcpc-br0.pid -s /tmp/ldhclnt
			syslog(LOG_INFO, "auto changed to DHCP...\n");
			//try dhcp
			system("killall udhcpc");
			system("udhcpc -i br0 -S -R");
			nvram_ra_set("ap_alert", "use dhcp connect to ac...");
			sleep(7);
		}
	}


__err:
	closelog();
	return 0;
}
