#include "apclid.h"
#include "wlconf.h"

static char __buffer[8196];

int wlconf_main(int argc, char *argv[])
{
	int fd, err;

	wireless_scan_head ct;// = (wireless_scan_head*)__buffer;
	memset(&ct, 0, sizeof(ct));

	if((fd=iw_sockets_open())<0) {
		logerr("init sock fd %s\n", strerror(errno));
		return 0;
	}
	logdbg("init sock ok...\n");

	struct iwreq wrq;
	iwprivargs *priv = NULL;

	

	// err = iw_scan(fd, "ra0", 0, &ct);
	// if(!err) {
	// 	wireless_scan *res = ct.result;
	// 	while(res) {
	// 		fprintf(stderr, "ssid: %s\n", res->b.name);
	// 		res = res->next;
	// 	}
	// }
	return err;
}