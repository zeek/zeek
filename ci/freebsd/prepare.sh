#!/bin/sh

echo "Preparing FreeBSD environment"
sysctl hw.model hw.machine hw.ncpu
set -e
set -x

env ASSUME_ALWAYS_YES=YES pkg bootstrap
pkg install -y bash git cmake swig bison python3 base64 flex ccache jq
pkg upgrade -y curl
pyver=$(python3 -c 'import sys; print(f"py{sys.version_info[0]}{sys.version_info[1]}")')
pkg install -y $pyver-sqlite3
python -m ensurepip --upgrade

python -m pip install websockets junit2html

# Spicy detects whether it is run from build directory via `/proc`.
echo "proc /proc procfs rw,noauto 0 0" >>/etc/fstab
mount /proc
