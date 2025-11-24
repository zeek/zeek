#! /usr/bin/env bash
#
# Shell script to install the latest version of certain
# Spicy analyzers using zkg *and* repackages build.tgz.
# This script should run after build.sh, but before the
# artifact upload happens.
set -eux

test -d ${CIRRUS_WORKING_DIR}/install

# Install prefix
PREFIX=${CIRRUS_WORKING_DIR}/install

export PATH=$PREFIX/bin:$PATH

zkg --version

ANALYZERS="
https://github.com/zeek/spicy-dhcp
https://github.com/zeek/spicy-http
"

for analyzer in $ANALYZERS; do
    echo Y | zkg -vvvvv install "${analyzer}"
done

# After installing analyzers, package up build.tgz (representing
# the contents of the installation directory). This overwrites any
# existing artifact created by build.sh
tar -czf ${CIRRUS_WORKING_DIR}/build.tgz ${CIRRUS_WORKING_DIR}/install
