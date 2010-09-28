#!/bin/sh
#
# This is a sample script to provide basic email notification for
# notices marked NOTICE_EMAIL .
#
# Usage: mail_notice "subject" recipient (optional config path)

notice="/tmp/bro.notice.$$"

# Clean up after ourselves.
trap "rm -f $notice; exit" 1 2 15

# Where are we located.
base=`dirname $0`

# Set up the environment.
if [ $3 ] ; then
	. $3
else
	. $base/../etc/bro.cfg
fi

echo "From:<$BRO_EMAIL_FROM>" > $notice
echo "To:<$2>" >> $notice
echo "Subject: Bro alarm: $1" >> $notice

sendmail <$notice -oi -f $BRO_EMAIL_FROM $2
rm -f $notice
