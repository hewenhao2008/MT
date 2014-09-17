#!/bin/sh

HOST=${1}
TYPE=${2}

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

if [ x"${TYPE}" == x"M50" ]; then
	#M50
	CURTVER=`nvram get ugw_version`
	if [ x"${LASTVER}" == x"${CURTVER}" ]; then
		LOG '已经是最新版本'
		exit 1
	fi
	
	if ! curl -o "${ROM}" "${HOST}${URL}" ; then
		LOG '下载升级包失败'
		exit 2
	fi
	
	if ! mtd update "${ROM}" ; then
		LOG '升级包格式不正确'
		exit 3
	fi
	
	LOG '升级结束'
	exit 0
elif [ x"${TYPE}" == x"SE3100" ]; then
	#SE3100
	CURTVER=`nvram get ugw_version`
	if [ x"${LASTVER}" == x"${CURTVER}" ]; then
		LOG 'Already last version.'
		exit 1
	fi
	
	if ! curl -o "${ROM}" "${HOST}${URL}" ; then
		LOG 'Download failed.'
		exit 2
	fi
	
	if ! mtd update "${ROM}" ; then
		LOG 'File format not matched.'
		exit 3
	fi
	
	LOG 'finished'
	exit 0
elif [ x"${TYPE}" == x"MR7620" ]; then
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
else
	#AP, unknown...
	LOG 'nothing todo && Finished'
	exit 0
fi


