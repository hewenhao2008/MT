#!/bin/sh

#sync date
ntpdate -u pool.ntp.org && nvram set ugw_timelast=`date +%s`

#3hours
sleep 10800

exit 0