#!/bin/sh

#init system
networks.sh

#start daemon
UGW_DAEMONS="nvram_daemon goahead dropbear"

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


