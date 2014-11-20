#!/bin/sh

HOST="id.ip-com.com.cn:8081"
TYPE="MR7620"

case $# in
	0)
		#default
	;;
	1)
		HOST=$1
	;;
	2)
		HOST=$1;
		TYPE=$2;
	;;
	*)
		HOST=$1;
		TYPE=$2;
	;;
esac


ROM="/tmp/imageX"
URL="/m50?cmd=getlastestfirmwarefile&type=${TYPE}"
GETVER="/m50?cmd=getlastestfirmwareversion&type=${TYPE}"
#curl -o /tmp/xxx http://www.baidu.com
WKDIR="/tmp/update"

LOG()
{
	logger -t online_upgrade $1
}

LASTVER=`curl ${HOST}${GETVER}`

# 无论成功失败, 都返回0, 让客户端重启, 更新AC端状态.
#AP, #LAST VERSION
if [ x"${LASTVER}" == x"" ]; then
	LOG 'No AP firware found.'
	exit 0
fi

CURTVER=`nvram get ugw_version`
if [ x"${CURTVER}" == x"${LASTVER}" ]; then
	LOG "Already last version."
	exit 0
fi

if ! curl -o "${ROM}" "${HOST}${URL}" ; then
	LOG 'Download failed.'
	exit 0
fi

# 将固件写入Kernel分区.
mkdir -p $WKDIR && cd $WKDIR
if tar xzf ${ROM}; then
	LOG "package images updated..."
	if [ -f ./update.sh ]; then
		chmod a+x ./update.sh
		nohup ./update.sh &
	fi
else
	LOG "firware images updated..."
	mtd_write -c write ${ROM} Kernel
	sync
	reboot
fi

LOG 'Finished'
sync && exit 0


