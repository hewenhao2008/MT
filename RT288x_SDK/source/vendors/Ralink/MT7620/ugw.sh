#!/bin/sh

#init system
#1. 将mac地址改成能识别的设备
MacOri=`ip link show dev eth2 | grep ether | awk '{print $2}'`
MacNew="${MacOri:0:2}:76:20:${MacOri:3:5}:${MacOri:15}"
ip link set dev eth2 down
ip link set dev eth2 address ${MacNew}
ip link set dev eth2 up
nvram set et0macaddr=${MacNew}

#startup networks
ugw_networks.sh

#recover system time.
date -s `nvram get ugw_timelast`

#start daemon, syslog
echo -n "Starting logging: "
start-stop-daemon -b -S -q -m -p /var/run/syslogd.pid --exec /sbin/syslogd -- -n
start-stop-daemon -b -S -q -m -p /var/run/klogd.pid --exec /sbin/klogd -- -n
echo "OK"
#dropbear sshd
echo -n "Starting dropbear sshd: "
start-stop-daemon -S -q -p /var/run/dropbear.pid --exec /usr/sbin/dropbear -- -p 12580
[ $? == 0 ] && echo "OK" || echo "FAIL"


#watchdog for daemons
StartProcess()
{
	case $1 in
		'syslogd')
			syslogd -S -b8
		;;

		*)
			$1 &
		;;
	esac
}
#UGW_DAEMONS="syslogd klogd nvram_daemon goahead apclid dropbear synctime.sh"
UGW_DAEMONS="syslogd klogd nvram_daemon apclid dropbear synctime.sh"
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


