#!/bin/sh
#
# script to check if rsync of logs has finished, and runs site-report.pl
#
# usage: frontend-mail-report.sh BroConfigFile
#

# where are we located
base=`dirname $0`
#set up the environment
if [ $1 ] ; then
   . $1
else
   . $base/../etc/bro.cfg
fi

echo " "
echo "`date`: checking if reports are ready to mail:" $BROHOME/logs/MailReports.$BRO_HOSTNAME

# only run if file $BROHOME/logs/MailReports.$BRO_HOSTNAME 
if [ -e $BROHOME/logs/MailReports.$BRO_HOSTNAME ] ; then
     echo "Reports ready: Running mail reports script"
     $BROHOME/scripts/mail_reports.sh $1
     rm $BROHOME/logs/MailReports.$BRO_HOSTNAME 
else
     echo "Reports not ready"
fi


