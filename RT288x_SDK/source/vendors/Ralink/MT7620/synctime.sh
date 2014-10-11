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
	iwpriv ra0 set AutoChannelSel=2;
}

while true; do

	#3hour
	if [ `expr $Counter % 180` -eq 0 ]; then
		SyncTime && logger "sync time finished." 
	fi

	#5min
	Random=`expr $Rand10 + $Counter`
	if [ `expr $Random % 15` -eq 0 ]; then
		AutoChannelSel && logger "auto channel selected $Random."
	fi

	#1min
	sleep 60
	Counter=`expr $Counter + 1`
done
