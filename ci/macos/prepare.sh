#!/bin/sh

echo "Preparing macOS environment"
sysctl hw.model hw.machine hw.ncpu hw.physicalcpu hw.logicalcpu
set -e
set -x

brew update
brew upgrade cmake
brew install openssl@3 swig bison flex ccache libmaxminddb

if [ $(sw_vers -productVersion | cut -d '.' -f 1) -lt 14 ]; then
    python3 -m pip install --upgrade pip
fi

python3 -m pip install --user --break-system-packages websockets
