#!/bin/sh
# script to check disk space and send email if getting full.
# constants are in BROHOME/etc/bro.cfg

. $BROHOME/etc/bro.cfg

if [ -n "$diskspace_enable" -a "x$diskspace_enable" != "xNO" ]; then
	prog="`basename $0 .sh`"
	t=/tmp/$prog.$$
	o=$prog.list
	df -kt ufs | sed -e '1d' -e 's/% / /' | \
	(while read filesys size used avail pct path ;do
		if [ "$pct" -ge "$diskspace_pct" ]; then
			echo "Filesystem $path ($filesys) getting full ($pct%)"
		fi
	done) > $t 2>&1
	if [ -s $t ]; then
		if [ -f $o ]; then
			diff $o $t > /dev/null 2>&1
			# remove temp file if no differences
			if [ $? = 0 ]; then
				rm $t
			else
				rm $o
			fi
		fi
		if [ -f $t ]; then
			mail -s "`hostname` disk space report" \
			    "$diskspace_watcher" < $t
			/bin/cp $t $o
		fi
	else
		rm -f $o
	fi
	rm -f $t
fi
