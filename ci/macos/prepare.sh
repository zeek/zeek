#!/bin/sh

echo "Preparing macOS environment"
sysctl hw.model hw.machine hw.ncpu hw.physicalcpu hw.logicalcpu
set -e
set -x

brew update
brew upgrade cmake
brew install cppzmq openssl@3 swig bison flex ccache libmaxminddb dnsmasq

# Upgrade pip so we have the --break-system-packages option.
python3 -m pip install --upgrade pip
python3 -m pip install --user --break-system-packages websockets
