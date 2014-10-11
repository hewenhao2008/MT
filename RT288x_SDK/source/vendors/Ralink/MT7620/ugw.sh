#!/bin/sh

#init system
#1. 将mac地址改成能识别的设备 ===> 改到nvram_daemon复位操作里面了.
MacOri=`ip link show dev eth2 | grep ether | awk '{print $2}'`
#MacNew="${MacOri:0:2}:76:20:${MacOri:3:5}:${MacOri:15}"
#ip link set dev eth2 down
#ip link set dev eth2 address ${MacNew}
#ip link set dev eth2 up
#nvram set et0macaddr=${MacNew}
nvram set et0macaddr=${MacOri}

#startup networks
ugw_networks.sh

#system time recovery.
date -s `nvram get ugw_timelast`

#start daemon
#1.syslog
echo -n "Starting logging: "
start-stop-daemon -b -S -q -m -p /var/run/syslogd.pid --exec /sbin/syslogd -- -n
start-stop-daemon -b -S -q -m -p /var/run/klogd.pid --exec /sbin/klogd -- -n
echo "OK"

#2.dropbear sshd
echo -n "Starting dropbear sshd: "
start-stop-daemon -S -q -p /var/run/dropbear.pid --exec /usr/sbin/dropbear -- -p 12580
[ $? == 0 ] && echo "OK" || echo "FAIL"


#insmod start auth, flowcontrol
#insmod /lib/modules/auth.ko

#start watchdog && exit.
ugw_daemons.sh &

exit 0
