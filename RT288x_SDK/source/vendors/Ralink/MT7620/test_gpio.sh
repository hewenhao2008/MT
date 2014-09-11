#!/bin/sh

# gpio l 4 1 1 10 1 1

NUM=0
while [ $NUM -lt 24 ]; do
	echo "test $NUM"
	gpio l $NUM 1 1 10 1 1

	sleep 3

	NUM=`expr $NUM + 1`
done
