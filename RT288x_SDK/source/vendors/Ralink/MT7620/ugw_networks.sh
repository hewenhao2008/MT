#!/bin/sh

#1. 配置交换机
#2. 配置网桥
#3. 配置IP地址
#4. 启动DHCP/路由....

F_LOG=/var/tmp/ugw_networks.log
MODPATH=/lib/modules

LOG()
{
	echo $1 >> $F_LOG
}

stop()
{
	LOG "stop networks..."

	ifconfig ra0 down
	#最多8个SSID, 目前只支持4个, 下发配置, SSID可能会变少, 所以不要读配置. #BssidNum=`nvram get BssidNum`
	BssidNum=4
	num=1
	while [ $num -lt $BssidNum ]; do
		LOG "stop ra$num..."

		ifconfig ra$num down
		num=`expr $num + 1`
	done

	#ifconfig eth2 down
	#ifconfig br0 down
	#brctl delbr br0

	LOG "rmmod wireless..."

	rmmod rt2860v2_ap
	#rmmod raeth
	#rmmod rt_rdm
}

start()
{
	#在rcS里面开启lo
	#ifconfig lo 127.0.0.1

	LOG "insmod ra wireless..."
	#叉叉模块.
	#insmod ${MODPATH}/rt_rdm.ko
	#insmod ${MODPATH}/raeth.ko
	insmod ${MODPATH}/rt2860v2_ap.ko

	#交换机
	config-vlan.sh 3 0
	
	LOG "apply wireless conf..."
	#生成无线配置, 供驱动读取
	ralink_init make_wireless_config rt2860

	#初始化MAC地址
	
	LOG "wakeup ra & eth devices..."
	#ifconfig ra0 0.0.0.0 1>/dev/null 2>&1
	ifconfig ra0 0.0.0.0
	ifconfig eth2 0.0.0.0
	
	#开启射频
	iwpriv ra0 set RadioOn=1
	
	LOG "create bridge devices..."
	#配置桥接
	brctl addbr br0
	brctl addif br0 eth2
	brctl addif br0 ra0
	
	#查找所有无线口,加入网桥
	BssidNum=`nvram get BssidNum`
	num=1
	while [ $num -lt $BssidNum ]; do
		LOG "wakeup ra$num ..."

		ifconfig ra$num 0.0.0.0 
		brctl addif br0 ra$num
		num=`expr $num + 1`
	done

	#修正br0的mac地址, 防止wlan的mac相同,导致自己上网慢.
	ip link set dev br0 address `nvram get et0macaddr`
	#判断DHCP是否开启(apcli 在连不上AC的时候, 能开启DHCP)
	ifconfig br0 0.0.0.0
	if [ x`nvram get lan_dhcp` == x'1' ]; then
		LOG "restart dhcp client..."
		#dhcp
		killall udhcpc;
		udhcpc -i br0 -S -R;
	else
		LOG "start static networks..."
		#static
		ADDR=`nvram get lan_ipaddr`
		MASK=`nvram get lan_netmask`
		GW=`nvram get lan_gateway`
		ip addr add dev br0 ${ADDR}/${MASK}
		ip route add default via ${GW}
	fi
}

reset()
{
	LOG "system hw reset deep..."

	ifconfig ra0 down
	BssidNum=4
	num=1
	while [ $num -lt $BssidNum ]; do
		LOG "stop ra$num..."

		ifconfig ra$num down
		num=`expr $num + 1`
	done

	ifconfig eth2 down
	ifconfig br0 down
	brctl delbr br0

	rmmod rt2860v2_ap
	rmmod raeth
	rmmod rt_rdm

	#reload modules
	LOG "reload modules up..."
	insmod ${MODPATH}/rt_rdm.ko
	insmod ${MODPATH}/raeth.ko
	insmod ${MODPATH}/rt2860v2_ap.ko

	#gennery start system.
	start
}

#只允许同时执行一个.
F_PID="/tmp/ugw_networks.pid"
echo $$ $F_PID
[ -f $F_PID ] && exit 0

LOG "ugw networks: $*"
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
			reset)
				reset
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
