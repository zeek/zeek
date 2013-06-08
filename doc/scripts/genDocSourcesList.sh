#!/usr/bin/env bash

# ./genDocSourcesList.sh [output file]
#
# Run this script to a generate file that's used to tell CMake about all the
# possible scripts for which reST documentation can be created.
#
# The optional argument can be used to avoid overwriting the file CMake uses
# by default.
#
# Specific scripts can be blacklisted below when e.g. they currently aren't
# parseable or they just aren't meant to be documented.

export LC_ALL=C # Make sorting stable.

blacklist ()
    {
    if [[ "$blacklist" == "" ]]; then
        blacklist="$1"
    else
        blacklist="$blacklist|$1"
    fi
    }

# files passed into this function are meant to be temporary workarounds
# because they're not finished or otherwise can't be loaded for some reason
tmp_blacklist ()
    {
    echo "Warning: temporarily blacklisted files named '$1'" 1>&2
    blacklist $1
    }

blacklist __load__.bro
blacklist test-all.bro
blacklist all.bro
blacklist init-default.bro
blacklist init-bare.bro

statictext="\
# DO NOT EDIT
# This file is auto-generated from the "genDocSourcesList.sh" script.
#
# This is a list of Bro script sources for which to generate reST documentation.
# It will be included inline in the CMakeLists.txt found in the same directory
# in order to create Makefile targets that define how to generate reST from
# a given Bro script.
#
# Note: any path prefix of the script (2nd argument of rest_target macro)
# will be used to derive what path under scripts/ the generated documentation
# will be placed.

set(psd \${PROJECT_SOURCE_DIR}/scripts)

rest_target(\${CMAKE_CURRENT_SOURCE_DIR} example.bro internal)
rest_target(\${psd} base/init-default.bro internal)
rest_target(\${psd} base/init-bare.bro internal)
"

if [[ $# -ge 1 ]]; then
    outfile=$1
else
    outfile=DocSourcesList.cmake
fi

thisdir="$( cd "$( dirname "$0" )" && pwd )"
sourcedir=${thisdir}/../..

echo "$statictext" > $outfile

bifs=`( cd ${sourcedir}/build/scripts/base && find . -name \*\.bif.bro | sort )`

for file in $bifs
do
    f=${file:2}
    echo "rest_target(\${CMAKE_BINARY_DIR}/scripts base/$f)" >> $outfile
done

scriptfiles=`( cd ${sourcedir}/scripts && find . -name \*\.bro | sort )`

for file in $scriptfiles
do
    f=${file:2}
    if [[ ! $f =~ $blacklist ]]; then
        echo "rest_target(\${psd} $f)" >> $outfile
    fi
done
