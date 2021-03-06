#!/bin/sh

[ x"${UGW_VERSION}" == x"" ] && exit 1
[ x"${ROOTDIR}" == x"" ] && exit 2
[ x"${ROMFSDIR}" == x"" ] && exit 3

FILES="ugw/ \
	etc/init.d/rcS "


cd ${ROMFSDIR} || exit 1
cp ${ROOTDIR}/update.sh ${ROMFSDIR}/
cp ${ROOTDIR}/images/*_uImage ${ROMFSDIR}/test.img

tar czvf ${ROOTDIR}/${UGW_VERSION} update.sh test.img $FILES || exit 101

#cleanup
rm ${ROMFSDIR}/update.sh
rm ${ROMFSDIR}/test.img

exit 0