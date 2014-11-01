#!/bin/sh

Counter=0
RandHex=`cat /proc/sys/kernel/random/uuid | awk -F- '{print toupper($1)}'`
Rand10=`echo "ibase=16;$RandHex" | bc`

SyncTime()
{
	#sync date
	ntpdate -u pool.ntp.org && nvram set ugw_timelast=`date +%s`
}

AutoChannelSel()
{
	#iwpriv ra0 set SiteSurvey=1; //noneed this
	Channel=`nvram get Channel`
	if [ x${Channel} != x"0" ]; then
		#不要设置信道,会闪断.
		#iwpriv ra0 set Channel=${Channel}
		return
	fi

	#switch channel
	RandHex=`cat /proc/sys/kernel/random/uuid | awk -F- '{print toupper($1)}'`
	CHRandom=`echo "ibase=16;$RandHex" | bc`
	Channel=`expr $CHRandom % 14`
	iwpriv ra0 set Channel=$Channel;

	logger "AutoChannelSel $Channel"
}

while true; do

	#3hour
	if [ `expr $Counter % 180` -eq 0 ]; then
		SyncTime && logger "sync time finished." 
	fi

	#30min
	if [ `expr $Counter % 30` -eq 0 ]; then
		tcfg.sh && logger "apply tc config."
	fi

	#5min
	Random=`expr $Rand10 + $Counter`
	if [ `expr $Random % 5` -eq 0 ]; then
		AutoChannelSel && logger "auto channel selected $Random."
	fi

	#1min
	sleep 60
	Counter=`expr $Counter + 1`
done
