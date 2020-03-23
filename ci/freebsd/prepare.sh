#!/bin/sh

echo "Preparing FreeBSD environment"
sysctl hw.model hw.machine hw.ncpu
set -e
set -x

env ASSUME_ALWAYS_YES=YES pkg bootstrap
pkg install -y bash git cmake swig30 bison python3 base64
pyver=`python3 -c 'import sys; print(f"py{sys.version_info[0]}{sys.version_info[1]}")'`
pkg install -y $pyver-sqlite3 $pyver-pip
( cd && mkdir -p ./bin && ln -s /usr/local/bin/python3 ./bin/python )
pip install junit2html
