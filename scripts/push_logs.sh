#!/bin/sh
#
# script to push logs from a bro host to a front end host, including a file "DoReports.HOST" telling
# the report generation script that the new days logs are ready to process
#
# usage: push_logs.sh hostname:path
#

# where are we located
base=`dirname $0`
#set the environment
. $base/../etc/bro.cfg

nice -n 20 /usr/local/bin/rsync -avzt $BROHOME/logs/ $1

# create and copy file to trigger report generation
touch /tmp/DoReports.$BRO_HOSTNAME
/usr/local/bin/rsync -avzt /tmp/DoReports.$BRO_HOSTNAME $1

# and if you need to sort the logs for Brooery, add this:
#ssh $1 "/usr/local/bro/scripts/log2gui.py -r /usr/local/bro/logs -l /usr/local/bro/sorted-logs"

