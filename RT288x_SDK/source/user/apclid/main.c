#include "apclid.h"
#include "api.h"

//全局变量
int ac_addr_invalid = 0;
extern int wlconf_main(int argc, char *argv[]);
extern int press_any_key_main(int argc, char *argv[]);

static void signal_handler(int sig)
{
	syslog(LOG_INFO, "apclid exiting...\n");
	closelog();
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

	if(strstr(argv[0], "apclid")==NULL) {
		logerr("unknown par[%s]\n", argv[0]);
		return 0;
	}

	openlog("apclid", 0, 0);

	if (argc>1 && strncmp(argv[1], "dbg", 3)==0) {
		//debug mode
	}else{
		if (daemon(1, 1) == -1) {
			logerr("daemon failed %d\n", errno);
			goto __err;
		}
	}

	init_handlers();

	logdbg("apclid starting...\n");

	ac_addr_invalid = 0;
	time_t start_ts = time(NULL);
	while(1) {
		//cleanup alert message
		nvram_ra_unset("ap_alert");
		nvram_ra_unset("ac_connected");


		//第一次, 等5min才转DHCP.
		int esp;
		do {
			//优先从配置读取ac地址.
			start_ap_client();

			esp = (time(NULL)-start_ts);
			logerr("connect failed, try %d secs\n", esp);
		} while (esp < 60);

		//超时, 连不上, 切换dhcp, 并且从广播获取AC地址.
		if (!nvram_ra_match("ap_standalone", "1")) {
			//5min, & not found ac. 
			ac_addr_invalid = 1; //广播获取AC地址

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
