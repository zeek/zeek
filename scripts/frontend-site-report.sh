#!/bin/sh
#
# script to check if rsync of logs has finished, and runs site-report.pl
#
# usage: frontend-site-report.sh BroConfigFile
#
#set -x

# where are we located
base=`dirname $0`
#set up the environment
if [ $1 ] ; then
   . $1
else
   . $base/../etc/bro.cfg
fi

echo " "
echo "`date`: checking if reports are ready to generate:" $BROHOME/logs/DoReports.$BRO_HOSTNAME

# only run if file $BROHOME/logs/DoReports.$BROHOST
if [ -e $BROHOME/logs/DoReports.$BRO_HOSTNAME ] ; then
     echo "rsync done: running site report script"
     rm $BROHOME/logs/DoReports.$BRO_HOSTNAME
     $BROHOME/scripts/site-report.pl --broconfig $1
     # create file indicating report is finished
     echo "creating file" $BROHOME/logs/MailReports.$BRO_HOSTNAME
     touch $BROHOME/logs/MailReports.$BRO_HOSTNAME
else
     echo "rsync not done"
fi

