#!/bin/sh

echo "Preparing macOS environment"
sysctl hw.model hw.machine hw.ncpu hw.physicalcpu hw.logicalcpu
set -e
set -x

brew update
brew upgrade cmake
brew install cppzmq openssl@3 python@3 swig bison flex ccache libmaxminddb dnsmasq krb5 node

which python3
python3 --version

python3 -m pip install --user --break-system-packages websockets
