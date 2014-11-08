#!/bin/sh

#watchdog for daemons
StartProcess()
{
	case $1 in
		'syslogd')
			syslogd -S -b8
		;;
		'dropbear')
			/etc/init.d/S50dropbear start
		;;

		*)
			$1 &
		;;
	esac
}


#syslogd
#klogd
#nvram_daemon
#goahead
#apclid
#dropbear synctime.sh authv httpauth httpd
UGW_DAEMONS="syslogd klogd nvram_daemon apclid dropbear synctime.sh httpd authv httpauth"
if [ x`nvram get UGWAuthEnable` == x"1" ]; then
	insmod /lib/modules/auth.ko
else
	#rmmod auth
	UGW_DAEMONS="syslogd klogd nvram_daemon apclid dropbear synctime.sh httpd"
fi

#放狗
while true;
do
	# 遛狗
	for d in $UGW_DAEMONS; 
	do
		if ! pidof $d > /dev/null 2>&1 ; then
			echo `date`" start daemon: $d" >> /tmp/daemon.log
			
			StartProcess $d
		fi
		
		sleep 1;
	done

	sleep 5;
done


