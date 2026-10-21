#!/bin/sh

echo "Preparing macOS environment"
sysctl hw.model hw.machine hw.ncpu hw.physicalcpu hw.logicalcpu
set -e
set -x

brew update
brew install -y cmake cppzmq openssl python@3 swig bison flex ccache libmaxminddb dnsmasq krb5

which python3
python3 --version

# Python3 on CircleCI in installed via pyenv. Make sure all of the versions of python are
# in pyenv, and then set to the latest as the global version. Otherwise pyenv uses an older
# version of Python than we build the Broker bindings against and things break.
if [[ "${CIRCLECI}" = "true" ]]; then
    ln -s $(brew --cellar python)/* ~/.pyenv/versions/
    pyenv versions
    pyenv global $(pyenv versions --bare | sort -V | tail -1)
fi

python3 -m pip install --user --break-system-packages websockets junit2html
