#!/bin/sh

FilesNum=`nvram get RecovFilesNum`

num=0
while [ $num -lt $FilesNum ]; do
	LOG "recover file$num after upgrade ..."

	FileToRecov=`nvram get RecovFile$num`
	if [ x"$FileToRecov" != x"" ]; then
		#cp file
		if [ -f $FileToRecov ]; then
			cp -af $FileToRecov /jffs2/ || echo "Error recover file $FileToRecov"
			nvram unset $FileToRecov
		else
			echo "File $FileToRecov not found."
		fi
	fi

	num=`expr $num + 1`
done

