#!/bin/sh

#install bro into your crontab for checkpointing

# source our cfg or guess at some defaults
if [ -r ./bro.cfg ] ; then
    . ./bro.cfg
else
    echo "Can't find bro.cfg, not installing crontab"
    #BRO_REPORT_START_TIME=0000
    #BROHOME="/usr/local/bro"
    #BRO_REPORT_INTERVAL=24
    #BRO_CHECKPOINT_INTERVAL=24
fi

RPT_MIN=`echo ${BRO_REPORT_START_TIME} | cut -c3-`
RPT_HR=`echo ${BRO_REPORT_START_TIME} | cut -c1,2`
RPT_INT=${BRO_REPORT_INTERVAL}
CHK_INT=${BRO_CHECKPOINT_INTERVAL}

if [ ${CHK_INT} -ge 24 ] ; then 
    CHK_INT=24
fi

if [ ${RPT_INT} -ge 24 ] ; then 
    RPT_INT=24
fi

create_cron()
{
    echo "BROHOME=${BROHOME}" >> /tmp/bro.crontab
    echo "# checkpoint Bro once a week" >> /tmp/bro.crontab
    echo "0 0 * * 1 ${BROHOME}/etc/bro.rc --checkpoint" >> /tmp/bro.crontab 
    #if [ ${CHK_INT} -eq 24 ] ; then 
    #    echo "0 0 * * 1 ${BROHOME}/etc/bro.rc --checkpoint" >> /tmp/bro.crontab 
    #else
    #    echo "0 0/${CHK_INT} * * * ${BROHOME}/etc/bro.rc --checkpoint" >> /tmp/bro.crontab 
    #fi
    if [ ${RPT_INT} -eq 24 ] ; then 
        echo "${RPT_MIN} ${RPT_HR} * * * ( nice -n 19 ${BROHOME}/scripts/site-report.pl )" >> /tmp/bro.crontab 
    else
        echo "${RPT_MIN} ${RPT_HR}/${RPT_INT} * * * ( nice -n 19 ${BROHOME}/scripts/site-report.pl )" >> /tmp/bro.crontab 
    fi

    echo "${RPT_MIN} $((${RPT_HR} + 3)) * * * (${BROHOME}/scripts/mail_reports.sh ${BROHOME}/etc/bro.cfg)" >> /tmp/bro.crontab 
    echo "0 3 * * * (${BROHOME}/scripts/bro_log_compress.sh)" >> /tmp/bro.crontab 

# insert rsync stuff, commented out, as an example:
    echo "# If you are process logs on a front end host, add this: " >> /tmp/bro.crontab 
    echo "#10 3 * * * (${BROHOME}/scripts/push_logs.sh FrontendHost)" >> /tmp/bro.crontab 

    crontab /tmp/bro.crontab 
    s=$? 
    if [ $s -ne 0 ] ; then 
        echo "Can NOT install crontab. Please see crontab.example" 
        echo "for an example crontab to install" 
    else 
        echo "" 
        echo "New crontab installed." 
        echo "" 
    fi 
    rm /tmp/bro.crontab 
    echo "" 
    echo "New crontab installed." 
    echo "" 
}

install_cron ()
{
    if [ -f /tmp/bro.crontab ] ; then                        
        rm  /tmp/bro.crontab  
    fi 
    if crontab -l > /tmp/bro.crontab ; then 
        if grep bro.rc /tmp/bro.crontab > /dev/null; then 
            echo "" 
            echo "Bro already installed in crontab!" 
            echo "Not installing a new crontab" 
            echo "" 
        else 
            create_cron
        fi 
    else 
        create_cron
    fi 
}

uninstall_cron()
{
    pid=$$
    crontab -l > /tmp/cron.orig.${pid} 2>&1 
    echo "status = $?"
    if [ $? -eq 0 ] ; then
        cat /tmp/cron.orig.${pid} | sed -e '/^.*bro_log_compress.sh)$/d' -e '/^.*etc\/bro.cfg; .\/mail_reports.sh)$/d' -e '/^.*.\/site-report.pl)$/d' -e '/^.*bro.rc --checkpoint$/d' > /tmp/cron.new.${pid}
    else
        echo "crontab missing?"
    fi
    echo "yes" | crontab -r 
    crontab /tmp/cron.new.${pid}
    echo "You can view your new crontab with a 'crontab -l'"
    echo "Your old crontab is in /tmp/cron.orig.${pid}"
}

case $1 in
    install)
        install_cron
        ;;
    uninstall)
        uninstall_cron
        ;;
esac
exit 0
