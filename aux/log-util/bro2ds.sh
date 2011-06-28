#!/bin/bash

VERBOSE=
COMPRESSION=lzf
TARGET=
SUFFIX=
TIME=
CLEANUP=0

while getopts ":bghlnvCL:" opt; do
	case $opt in
	v)
	  	echo "Turning on verbose output."
	  	VERBOSE=-v
	  	;;
	n)
	  	echo "Compression disabled."
	  	COMPRESSION=none
	  	SUFFIX=
	  	;;
	g)
	  	echo "Using GZIP compression."
	  	COMPRESSION=gz
	  	SUFFIX=.gz
	  	;;
	b)
	  	echo "Using BZ2 compression."
	  	COMPRESSION=bz2
	  	SUFFIX=.bz2
	  	;;
	l)
	  	echo "Using LZF compression."
	  	COMPRESSION=lzf
	  	SUFFIX=.lzf
	  	;;
	h)
	  	echo "Usage: bro2ds.sh -[bglnvC] -L <logfile>"
	  	echo "   -v : verbose output"
	  	echo "   -n : use no compression"
	  	echo "   -l : use lzf compression"
	  	echo "   -g : use gz compression"
	  	echo "   -b : use bz2 compression"
		echo "   -C : clean up intermediate XML / CSV files"
	  	echo "   -L : process logfile <logfile>"
		exit 0
		;;
	L)
	  	TARGET=$OPTARG
	  	echo "Using logfile $OPTARG"
	  	;;
	T)
		TIME="time"
		echo "Timing this run."
	    ;;
	C)
		CLEANUP=1
		echo "Cleaning up after myself"
		;;
	\?)
	    echo "Invalid option: -$OPTARG" >&2
	    ;;
	esac
done

if [ x$TARGET == "x" ]; then
	echo "No logfile specified; re-run the utility with the -L option."
	exit -1
fi

./bro2csv.py $VERBOSE $TARGET

if [ $? -ne 0 ]; then
	echo "BRO log to CSV conversion failed.  Aborting..."
	exit -1
fi

TARGET_BASE=`echo $TARGET | sed 's/\.log//g'`
echo "Building DataSeries file: $TARGET_BASE$SUFFIX.ds"
$TIME csv2ds --compress-$COMPRESSION --xml-desc-file=$TARGET.xml $TARGET.csv $TARGET_BASE$SUFFIX.ds

if [ $CLEANUP -ne 0 ]; then
	rm -f $TARGET.xml $TARGET.csv
fi

