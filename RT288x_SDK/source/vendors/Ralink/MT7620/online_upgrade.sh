#!/bin/sh

HOST=${1}
TYPE=${2}

ROM="/tmp/imageX"
URL="/m50?cmd=getlastestfirmwarefile&type=${TYPE}"
GETVER="/m50?cmd=getlastestfirmwareversion&type=${TYPE}"
#curl -o /tmp/xxx http://www.baidu.com

LASTVER=`curl ${HOST}${GETVER}`

if [ x"${TYPE}" == x"M50" ]; then
	#M50
	CURTVER=`nvram get ugw_version`
	if [ x"${LASTVER}" == x"${CURTVER}" ]; then
		logger '已经是最新版本'
		exit 1
	fi
	
	if ! curl -o "${ROM}" "${HOST}${URL}" ; then
		logger '下载升级包失败'
		exit 2
	fi
	
	if ! mtd update "${ROM}" ; then
		logger '升级包格式不正确'
		exit 3
	fi
	
	logger '升级结束'
	exit 0
elif [ x"${TYPE}" == x"SE3100" ]; then
	#SE3100
	CURTVER=`nvram get ugw_version`
	if [ x"${LASTVER}" == x"${CURTVER}" ]; then
		logger 'Already last version.'
		exit 1
	fi
	
	if ! curl -o "${ROM}" "${HOST}${URL}" ; then
		logger 'Download failed.'
		exit 2
	fi
	
	if ! mtd update "${ROM}" ; then
		logger 'File format not matched.'
		exit 3
	fi
	
	logger 'finished'
	exit 0
elif [ x"${TYPE}" == x"MR7620" ]; then
	#AP, #LAST VERSION
	if [ x"${LASTVER}" == x"" ]; then
		logger 'No AP firware found.'
		exit 1
	fi
	LASTVER=`echo ${LASTVER} | sed -e 's/-/\./g'`

	CURTVER=`nvram get ugw_version`
	if [ x"${CURTVER}" == x"${LASTVER}" ]; then
		logger "Already last version."
		exit 1
	fi

	if ! curl -o "${ROM}" "${HOST}${URL}" ; then
		logger 'Download failed.'
		exit 2
	fi

	# 将固件写入Kernel分区.
	mtd_write -c write ${ROM} Kernel

	logger 'Finished'
	exit 0
else
	#AP, unknown...
	logger 'nothing todo && Finished'
	exit 0
fi


