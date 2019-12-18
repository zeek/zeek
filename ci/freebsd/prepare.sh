#!/bin/sh

echo "Preparing FreeBSD environment"
sysctl hw.model hw.machine hw.ncpu
set -e
set -x

env ASSUME_ALWAYS_YES=YES pkg bootstrap
pkg install -y bash git cmake swig30 bison python3 py36-sqlite3 py36-pip base64
( cd && mkdir -p ./bin && ln -s /usr/local/bin/python3 ./bin/python )
pip install junit2html
