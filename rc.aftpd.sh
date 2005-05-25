#!/bin/sh
#
# $Id: rc.aftpd.sh,v 1.1 2005/05/25 20:01:41 dancy Exp $

installdir=/usr/local/sbin/aftpd

case "$1" in
'start')
	if [ -x ${installdir}/aftpd ]; then
		${installdir}/aftpd
	fi
	;;

'stop')
	/usr/bin/killall aftpd
	;;

*)
	echo "Usage: $0 { start | stop }"
	exit 1
	;;
esac
exit 0
