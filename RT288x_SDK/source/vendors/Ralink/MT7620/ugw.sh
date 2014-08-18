#!/bin/sh

UGW_DAEMONS="nvram_daemon goahead"


while true;
do
	# 遛狗
	for d in $UGW_DAEMONS; 
	do
		if ! pidof $d; then
			echo `date`" start daemon: $d" >> /tmp/daemon.log
			
			$d &
		fi
		
		sleep 3;
	done

	sleep 3;
done


