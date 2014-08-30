#!/bin/sh

#init system

#startup networks
ugw_networks.sh

#start daemon
UGW_DAEMONS="syslogd klogd nvram_daemon goahead apclid dropbear"
while true;
do
	# 遛狗
	for d in $UGW_DAEMONS; 
	do
		if ! pidof $d > /dev/null 2>&1 ; then
			echo `date`" start daemon: $d" >> /tmp/daemon.log
			
			$d &
		fi
		
		sleep 1;
	done

	sleep 5;
done


