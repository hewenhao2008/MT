#include "apclid.h"
#include "wlconf.h"

static char __buffer[8196];

static void useage(void)
{
	fprintf(stderr, "wlconf raX ugw\n");
	fprintf(stderr, "wlconf raX ugw <stainfo,xx:xx:xx:xx:xx:xx/stalist>\n");
}

int wlconf_main(int argc, char *argv[])
{
	int fd, err;
	char buffer[8196];
	char *ifname = (argc>1?argv[1]:"ra0");
	char *cmd = (argc>2)?argv[2]:"ugw";
	char *sub_cmd = (argc>3?argv[3]:"stainfo");

	wireless_scan_head ct;// = (wireless_scan_head*)__buffer;
	memset(&ct, 0, sizeof(ct));

	if((fd=iw_sockets_open())<0) {
		logerr("init sock fd %s\n", strerror(errno));
		return 0;
	}
	//logdbg("init sock ok...\n");

	int n, i, priv_cmd;
	struct iwreq wrq;
	iwprivargs *priv;

	/* Read the private ioctls */
	n = iw_get_priv_info(fd, ifname, &priv);
	if(n<0){
		logerr("%s not wireless port.\n", ifname);
		return -1;
	}

	for (i = 0; i < n; ++i) {
		if(strncmp(priv[i].name, cmd, 3)==0) {
			priv_cmd = priv[i].cmd;
			break;
		}
	}
	if(i==n){
		logerr("not supported cmd.\n");
		return 0;
	}

	snprintf(buffer, sizeof(buffer), sub_cmd);

	wrq.u.data.length = sizeof(buffer);
	wrq.u.data.pointer = buffer;
	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

	//logdbg("sub[%s], priv: %x\n", priv[i].name, priv_cmd);
	if(priv){
		free(priv);
	}

	if(ioctl(fd, priv_cmd, &wrq) < 0) {
		logerr("ioctl failed %s\n", strerror(errno));
		return(-1);
    }

    fprintf(stderr, "wrq->length:%d\n", wrq.u.data.length);
    fprintf(stdout, "%s\n", wrq.u.data.pointer);

    fflush(stdout);
	return err;
}