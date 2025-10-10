#!/bin/sh

echo "Preparing macOS environment"
sysctl hw.model hw.machine hw.ncpu hw.physicalcpu hw.logicalcpu
set -e
set -x

brew update
brew upgrade cmake
brew install cppzmq openssl@3 python@3.13 swig bison flex ccache libmaxminddb dnsmasq krb5

# Homebrew doesn't put older versions of python into the PATH by default.
export PATH=/opt/homebrew/opt/python@3.13/libexec/bin:${PATH}
echo "export PATH=/opt/homebrew/opt/python@3.13/libexec/bin:${PATH}" >>~/.zshrc

which python3
python3 --version

python3 -m pip install --user --break-system-packages websockets
