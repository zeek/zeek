#!/bin/sh 
# very simple script to compress old files and remove older files
# You will probably want to do something more sophisticated for
#	a production bro installation (e.g.: Integrate this into
#	your backup scripts)
#
# Note: might want to check current disk space and just exit
#	if there is lots of space
#
#set -x

if [ $BROHOME ] ; then
  . $BROHOME/etc/bro.cfg
else
  # if BROHOME is not set, try default location
  . /usr/local/bro/etc/bro.cfg
fi

#echo found BROLOGS in bro.cfg: $BROLOGS
logdir=$BROLOGS/

if [ ! -d $logdir ] ; then
    echo "Error: log file directory not found"
    exit
fi

Days2deletion=$BRO_DAYS_2_DELETION
Days2compression=$BRO_DAYS_2_COMPRESSION

echo "Deleting files older than $BRO_DAYS_2_DELETION days, and compressing files older than $BRO_DAYS_2_COMPRESSION days"

echo "Checking directory: $BRO_LOG_ARCHIVE"
# first delete old archives
filelist=`find $BRO_LOG_ARCHIVE -type f -mtime +$Days2deletion -print `
#echo list of files to delete: $filelist

for file in $filelist
   do
        echo removing: $file
	rm -f $file
   done

# next delete old sorted log files needed by Brooery
if [ -d $BROOERY_LOGS ] ; then
   echo "Checking directory: $BROOERY_LOGS"
   filelist=`find $BROOERY_LOGS -type f -mtime +$Days2deletion -print `
   #echo list of files to delete: $filelist

   for file in $filelist
      do
           echo removing: $file
	   rm -f $file
      done
fi

echo "Checking directory: $logdir"
# also check for any old stuff in the main log dir (just in case)
filelist=`find $logdir -type f -mtime +$Days2deletion -print `
#echo list of files to delete: $filelist

for file in $filelist
   do
        echo removing: $file
	rm -f $file
   done

#delete core files that are more than 4 days old
filelist=`find $logdir -name "*core*" -mtime +4 -print `
for file in $filelist
   do
        echo removing: $file
	rm -f $file
   done


filelist=`find $logdir -type f -mtime +$Days2compression -print `
#echo list of files to compress: $filelist

for file in $filelist
   do
        echo compressing: $file
	nice gzip $file
   done

echo Moving compressed files to archive dir: $BRO_LOG_ARCHIVE
mv $logdir/*.gz $BRO_LOG_ARCHIVE
echo Done.
exit
