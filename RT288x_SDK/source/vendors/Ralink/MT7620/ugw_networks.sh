#!/bin/sh

#1. 配置交换机
#2. 配置网桥
#3. 配置IP地址
#4. 启动DHCP/路由....

stop()
{
	ifconfig ra0 down
	ifconfig eth2 down

	ifconfig br0 down
	brctl delbr br0
}

start()
{
	ifconfig lo 127.0.0.1

	#交换机
	config-vlan.sh 3 0
	
	#生成无线配置, 供驱动读取
	ralink_init make_wireless_config rt2860

	#初始化MAC地址
	
	#ifconfig ra0 0.0.0.0 1>/dev/null 2>&1
	ifconfig ra0 0.0.0.0
	ifconfig eth2 up
	
	#开启射频
	iwpriv ra0 set RadioOn=1
	
	#配置桥接
	brctl addbr br0
	brctl addif br0 eth2
	brctl addif br0 ra0
	
	#查找所有无线口,加入网桥
	BssidNum=`nvram get BssidNum`
	num=1
	while [ $num -lt $BssidNum ]; do
		ifconfig ra$num 0.0.0.0 
		brctl addif br0 ra$num
		num=`expr $num + 1`
	done

	#判断DHCP是否开启
	ifconfig br0 192.168.1.110
}

#只允许同时执行一个.
F_PID="/tmp/ugw_networks.pid"
echo $$ $F_PID
[ -f $F_PID ] && exit 0

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
		esac
	;;
	*)
		start
	;;
esac

rm -fr $F_PID
