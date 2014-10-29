#!/bin/sh

for i in 0 1 2 3; do
	rate=`nvram get ra${i}_upflowlimit`
	if [[ "x$rate" != x"" ]]; then
		echo $rate > /sys/module/suq/parameters/ssid${i}_xmit_limit
	fi
	rate=`nvram get ra${i}_downflowlimit`
	if [[ "x$rate" != x"" ]]; then
		echo $rate > /sys/module/suq/parameters/ssid${i}_recv_limit
	fi
done
