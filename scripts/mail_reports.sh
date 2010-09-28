#!/bin/sh
#
# Shell script to mail reports, should be called from
# crontab
# $Id: mail_reports.sh 1554 2005-10-24 22:20:26Z tierney $
#
# Usage: mail_reports.sh configFile (default config file = ../etc/bro.cfg)

gpg_error=""
sent_message=""
tmp_file="/tmp/bro.report.$$"

# Clean up after ourselves.
trap "rm $tmp_file; exit" 1 2 15

# Where are we located.
base=`dirname $0`

# Set up the environment.
if [ $1 ] ; then
   . $1
else
   . $base/../etc/bro.cfg
fi

for f in /usr/bin/sendmail /usr/sbin/sendmail /usr/lib/sendmail; do
   if [ -x ${f} ]; then
	    d="`dirname ${f}`"
	    PATH="${d}:${PATH}"
	    export PATH
   fi
done

# find the newest report in the report directory
report=`ls -1t $BRO_REPORT_DIR/$BRO_SITE_NAME*.rpt | head -1`
report_interval=`grep Report $report | awk '{print $6,"-",$9}'`

# set up temporary report with subject line embedded
report_subject="Subject: $BRO_HOSTNAME Report: $report_interval"

# and email it
# if encrypted make sure we have a good (gpg) bin  and keys
if [ $BRO_ENCRYPT_EMAIL = "YES" ] ; then
    if [ -x $BRO_GPG_BIN ] ; then
	for recpt in $BRO_EMAIL_LOCAL ;  do
	    echo "From: <$BRO_EMAIL_FROM>" > $tmp_file
	    echo "To: <$recpt>" >> $tmp_file
	    echo "$report_subject" >> $tmp_file
	    cat $report | $BRO_GPG_BIN --yes -ea -r $recpt >> $tmp_file
	    # If the encryption fails, send it unencrypted
	    if [ $? -ne 0 ] ; then
		echo "From:<$BRO_EMAIL_FROM>" > $tmp_file
		echo "To: <$recpt>" >> $tmp_file
		echo "$report_subject" >> $tmp_file
		cat $report >> $tmp_file
	    fi
	    cat $tmp_file | sendmail -oi -f $BRO_EMAIL_FROM $recpt
	done
	sent_message="1"
	rm $tmp_file
    else
	gpg_error="1"
    fi
fi

# if there was an error or we are sending unencrypted ...
if [ -z $sent_message ] ; then
    for recpt in $BRO_EMAIL_LOCAL ;  do
	echo "From: <$BRO_EMAIL_FROM>" > $tmp_file
	echo "To: <$recpt>" >> $tmp_file
	echo "$report_subject" >> $tmp_file
	cat $report >> $tmp_file
	if [ $gpg_error ] ; then
	    echo "Invalid gpg bin $BRO_GPG_BIN" >> $tmp_file
	fi
	cat $tmp_file | sendmail -oi -f $BRO_EMAIL_FROM $recpt
    done
    rm  $tmp_file
fi

exit 0
