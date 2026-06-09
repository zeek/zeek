#!/bin/sh

echo "Preparing macOS environment"
sysctl hw.model hw.machine hw.ncpu hw.physicalcpu hw.logicalcpu
set -e
set -x

brew update
brew install cmake cppzmq openssl@3 python@3 swig bison flex ccache libmaxminddb dnsmasq krb5

which python3
python3 --version

# Python3 on CircleCI in installed via pyenv, which means we can install the modules
# directly into the pyenv without involving the user or system directory.
if [[ "${CIRCLECI}" = "true" ]]; then
    python3 -m pip install websockets junit2html
else
    python3 -m pip install --user --break-system-packages websockets junit2html
fi
