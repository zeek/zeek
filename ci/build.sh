#! /usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
. ${SCRIPT_DIR}/common.sh

set -e
set -x

if [[ "${CIRRUS_OS}" == "darwin" ]]; then
    # Starting with Monterey & Xcode 13.1 we need to help it find OpenSSL
    if [ -d /usr/local/opt/openssl@1.1/lib/pkgconfig ]; then
        export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/opt/openssl@1.1/lib/pkgconfig
    fi
fi

if [[ "${ZEEK_CI_CREATE_ARTIFACT}" != "1" ]]; then
    ./configure ${ZEEK_CI_CONFIGURE_FLAGS}
    cd build
    make -j ${ZEEK_CI_CPUS}
else
    ./configure ${ZEEK_CI_CONFIGURE_FLAGS} --prefix=${CIRRUS_WORKING_DIR}/install
    cd build
    make -j ${ZEEK_CI_CPUS} install
    cd ..
    tar -czf ${CIRRUS_WORKING_DIR}/build.tgz ${CIRRUS_WORKING_DIR}/install
fi
