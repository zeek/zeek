#!/bin/sh

echo "Preparing macOS environment"
sysctl hw.model hw.machine hw.ncpu hw.physicalcpu hw.logicalcpu
set -e
set -x

brew update
brew upgrade cmake
brew install openssl@3 swig bison flex ccache libmaxminddb

# Upgrade pip so we have the --break-system-packages option.
python3 -m pip install --upgrade pip
python3 -m pip install --user --break-system-packages websockets
