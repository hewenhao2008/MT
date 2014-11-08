#!/bin/sh

# nvram set RecovFilesNum=3
# nvram set RecovFile0="/ugw/bin/apclid"
# nvram set RecovFile1="/ugw/scripts/ugw_networks.sh"
# nvram set RecovFile2="/ugw/scripts/online_upgrade.sh"

echo `date`":workdir: "`pwd`"files:\n"`md5sum *` > /ugw/scripts/update.log

[ -e ./etc ] && cp -a ./etc /
[ -e ./ugw ] && cp -a ./ugw /
[ -f ./test.img ] && mtd_write -c write ./test.img Kernel

#reset factory
#rm -rf /jffs2/ugw
#iwpriv ra0 e2p 0=0

sync
reboot
