#!/bin/sh

F_LOG=/var/tmp/ugw_services.log

LOG()
{
	echo $1 >> $F_LOG
}

stop()
{
	LOG "stop networks..."

	ugw_networks.sh stop

	LOG "stop dog..."
	killall ugw_daemons.sh
	killall authv
	killall lua
	killall apclid

	#rmmod
	rmmod auth
}

start()
{
	LOG "start networks..."

	ugw_networks.sh start

	LOG "stop 3p auth, restart by dog..."
	nohup ugw_daemons.sh &
}

#只允许同时执行一个.
F_PID="/tmp/ugw_services.pid"
echo $$ $F_PID
[ -f $F_PID ] && exit 0

LOG "ugw services: $*"
#main
case $# in
	0)
		start
	;;
	1)
		case $1 in
			restart)
				stop
				start
			;;
			stop)
				stop
			;;
			start)
				start
			;;
			*)
				start
			;;
		esac
	;;
	*)
		start
	;;
esac

rm -fr $F_PID
