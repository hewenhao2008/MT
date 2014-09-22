#include "rt_config.h"

static char ugw_io_buffer[8192];
#define UGW_IO_SIZE sizeof(ugw_io_buffer)

static INT	Ugw_StaInfo_Proc(
	IN	PRTMP_ADAPTER	pAd, 
	IN	RTMP_IOCTL_INPUT_STRUCT *wrq,
	int argc, char **argv)
{
	int Status = NDIS_STATUS_SUCCESS;
	INT i;/*, QueIdx=0; */
    PSTRING msg = ugw_io_buffer;
    PSTRING sub_req = NULL;
	int len = 0, n;
	int sta_count = 0;

	if(argc>0 && argv[0]) {
		sub_req = argv[0];
	}

	NdisZeroMemory(msg, UGW_IO_SIZE);

	for (i=0; i<MAX_LEN_OF_MAC_TABLE; i++)
	{
		PMAC_TABLE_ENTRY pEntry = &pAd->MacTab.Content[i];

		if (IS_ENTRY_CLIENT(pEntry) && (pEntry->Sst == SST_ASSOC))
		{
			sta_count ++;
			if(sub_req && strncmp(sub_req, "count", 5) == 0) {
				continue;
			}
			if((len + 128) >= (UGW_IO_SIZE)){
				DBGPRINT(RT_DEBUG_ERROR, ("buffer overflow.\n"));
				break;	
			}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"macaddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
				pEntry->Addr[0], pEntry->Addr[1], pEntry->Addr[2],
				pEntry->Addr[3], pEntry->Addr[4], pEntry->Addr[5]);
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"ifidx=%d\n", (int)pEntry->apidx);//mbss number
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"aid=%d\n", (int)pEntry->Aid);
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"authm=%d\n", (int)pEntry->AuthMode);
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"status=%d\n", (int)pEntry->Sst);
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"rssi=%d\n", (int)RTMPAvgRssi(pAd, &pEntry->RssiSample));
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"in_network=%d\n", (int)pEntry->StaConnectTime);
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"idle=%d\n", (int)pEntry->NoDataIdleCount);
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"dead_line=%d\n", (int)pEntry->AssocDeadLine);
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"tx_rate=%d\n", RateIdToMbps[(int)pEntry->CurrTxRate]);
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"rx_rate=%d\n", (int)pEntry->LastRxRate);
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"quality=%d\n", (int)pEntry->ChannelQuality);
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"tx_bytes=%d\n", (int)pEntry->TxBytes);
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"rx_bytes=%d\n", (int)pEntry->RxBytes);
			if(n>0){len += n;}else{break;}
			n=snprintf(msg+len, UGW_IO_SIZE - len,"\n");
			if(n>0){len += n;}else{break;}
		}
	}
	n=snprintf(msg+len, UGW_IO_SIZE - len,"sta_count=%d\n", sta_count);
	//if(n>0){len += n;}

	/* for compatible with old API just do the printk to console*/
	return Status;
}

static INT	Ugw_ApInfo_Proc(
	IN	PRTMP_ADAPTER	pAd, 
	IN	RTMP_IOCTL_INPUT_STRUCT *wrq,
	int argc, char **argv)
{
	INT Status = NDIS_STATUS_SUCCESS;
	char *msg = ugw_io_buffer;
	int sta_count = 0, assoc = 1;
	//int channel = pAd->CommonCfg.Channel;
	int noise = 0, txpower = 0;
	//Channel:pAd->CommonCfg.Channel
	//noise: 
	//sta num
	char *sub_req = (argc>0 && argv[0]?argv[0]:"channel");

	NdisZeroMemory(msg, UGW_IO_SIZE);

	if (!strcmp(sub_req, "channel")) {
		sprintf(msg, "%d", (int)pAd->CommonCfg.Channel);
	}else if(!strcmp(sub_req, "conn") || (assoc=strcmp(sub_req, "assoc"))==0 ) {
		int i;
		for (i=0; i<MAX_LEN_OF_MAC_TABLE; i++) {
			PMAC_TABLE_ENTRY pEntry = &pAd->MacTab.Content[i];
			if (IS_ENTRY_CLIENT(pEntry) && 
				((assoc==0 && (pEntry->Sst == SST_ASSOC)) || (pEntry->Sst == SST_AUTH))) {
				sta_count ++;
			}
		}
		sprintf(msg, "%d", sta_count);
	}else if(!strcmp(sub_req, "noise")) {
		sprintf(msg, "%d", noise);
	}else if(!strcmp(sub_req, "txpower")) {
		sprintf(msg, "%d", txpower);
	}else{
		sprintf(msg, "-");
	}
	//fmt 

	return Status;
}

static INT	Ugw_Scan_Proc(
	IN	PRTMP_ADAPTER	pAd, 
	IN	RTMP_IOCTL_INPUT_STRUCT *wrq,
	int argc, char **argv)
{
	NDIS_802_11_SSID Ssid;
	PBSS_ENTRY	pBss;
	INT Status = NDIS_STATUS_SUCCESS, WaitCnt=0;
	PSTRING msg = ugw_io_buffer;
	int len, n, i;

	if (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_INTERRUPT_IN_USE))
	{
		DBGPRINT(RT_DEBUG_ERROR, ("INFO::Network is down!\n"));
		return -ENETDOWN;   
	}

	NdisZeroMemory(&Ssid, sizeof(Ssid));

	ApSiteSurvey(pAd, &Ssid, SCAN_PASSIVE, FALSE);

	//wait finished
	while ((ScanRunning(pAd) == TRUE) && (WaitCnt++ < 200))
		OS_WAIT(500);

	len = 0;
	for(i=0; i<pAd->ScanTab.BssNr ;i++)
	{
		pBss = &pAd->ScanTab.BssEntry[i];
		
		if( pBss->Channel==0)
			break;

		n=snprintf(msg+len, UGW_IO_SIZE-len, "BSSID=%02x:%02x:%02x:%02x:%02x:%02x\n", 
			pBss->Bssid[0],pBss->Bssid[1],pBss->Bssid[2],
			pBss->Bssid[3],pBss->Bssid[4],pBss->Bssid[5]);
		len += n;
		n=snprintf(msg+len, UGW_IO_SIZE-len, "SSID=%s\n", pBss->Ssid);
		len += n;
		n=snprintf(msg+len, UGW_IO_SIZE-len, "chanspec=%d\n", (int)pBss->Channel);
		len += n;
		n=snprintf(msg+len, UGW_IO_SIZE-len, "RSSI=%d\n", (int)pBss->Rssi);
		len += n;
		n=snprintf(msg+len, UGW_IO_SIZE-len, "noise=%d\n", pBss->MinSNR);
		len += n;
		n=snprintf(msg+len, UGW_IO_SIZE-len, "timestamp=0\n\n");
		len += n;
	}

	return Status;
}

static struct {
	PSTRING name;
	INT (*set_proc)(IN PRTMP_ADAPTER pAd, IN RTMP_IOCTL_INPUT_STRUCT *wrq, 
		int argc, char **argv);
} *PRTMP_PRIVATE_UGW_PROC, RTMP_PRIVATE_UGW_PROC[] = {
	{"info",						Ugw_ApInfo_Proc},
	{"stainfo",						Ugw_StaInfo_Proc},
	{"scan",						Ugw_Scan_Proc},
	{NULL, NULL},
};


INT RTMPIoctlGetUGW(
	IN PRTMP_ADAPTER pAd,
	IN RTMP_IOCTL_INPUT_STRUCT *wrq)
{
	PSTRING this_char;
	PSTRING value;
	INT Status = NDIS_STATUS_SUCCESS;
	char buffer[128];
	int argc = 0, i;
	char *argv[16];

	value = buffer;
	strncpy(buffer, wrq->u.data.pointer, sizeof(buffer));
	while ((this_char = strsep(&value, ",")) != NULL) 
	{
		if (!*this_char)
			 continue;

		argv[argc] = this_char;
		argc ++;
	}

	if(!argc) {
		DBGPRINT(RT_DEBUG_ERROR, ("no argument found: [%s]\n", buffer));
		return Status;
	}

#if 1
	printk("[%d] args:\t", argc);
	for(i=0; i<argc; i++) {
		printk("<%s>", argv[i]);
	}
	printk("\n");
#endif

	for (PRTMP_PRIVATE_UGW_PROC = RTMP_PRIVATE_UGW_PROC; PRTMP_PRIVATE_UGW_PROC->name; PRTMP_PRIVATE_UGW_PROC++)
	{
		if (!strcmp(argv[0], PRTMP_PRIVATE_UGW_PROC->name)) {
			int n;

			Status = PRTMP_PRIVATE_UGW_PROC->set_proc(pAd, wrq, argc-1, &argv[1]);
			
			wrq->u.data.length = strlen(ugw_io_buffer)+1;
			if ((n=copy_to_user(wrq->u.data.pointer, ugw_io_buffer, wrq->u.data.length))!=0)
			{
				DBGPRINT(RT_DEBUG_ERROR, ("copy_to_user(%d) fail.\n", n));
				Status = -EINVAL;
			}
			DBGPRINT(RT_DEBUG_WARN, ("len:%d copy to user\n", wrq->u.data.length));
			break;
		}
	}

	if(PRTMP_PRIVATE_UGW_PROC->name == NULL)
	{  /*Not found argument */
		Status = -EINVAL;
		DBGPRINT(RT_DEBUG_ERROR, ("IOCTL::(iwpriv) Command not Support [%s=%s]\n", buffer, argv[0]));
	}	
	return Status;
}

