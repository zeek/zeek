#! /usr/bin/env bash

set -x

# NOTE: We do not use `nproc` since on some platforms it needs to be explicitly
# installed while `getconf` is POSIX.
ZEEK_CI_CPUS=${ZEEK_CI_CPUS:-$(getconf _NPROCESSORS_ONLN)}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

set -e

# TODO: Is this necessary anymore?
if [[ "${ZEEK_CI_RUNNER_OS}" == "macos" ]]; then
    # Starting with Monterey & Xcode 13.1 we need to help it find OpenSSL
    if [ -d /usr/local/opt/openssl@1.1/lib/pkgconfig ]; then
        export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/opt/openssl@1.1/lib/pkgconfig
    fi
fi

if [[ "${ZEEK_CI_CREATE_ARTIFACT}" != "1" && "${ZEEK_CI_CREATE_ARTIFACT}" != "true" ]]; then
    ./configure ${ZEEK_CI_CONFIGURE_FLAGS} ${ZEEK_CI_CONFIGURE_FLAGS_EXTRA}
    cd build
    make -j ${ZEEK_CI_CPUS}
else
    ./configure ${ZEEK_CI_CONFIGURE_FLAGS} ${ZEEK_CI_CONFIGURE_FLAGS_EXTRA} --prefix=${ZEEK_CI_WORKING_DIR}/install
    cd build
    make -j ${ZEEK_CI_CPUS} install
    cd ..
    tar -czf ${ZEEK_CI_WORKING_DIR}/build.tgz ${ZEEK_CI_WORKING_DIR}/install
fi
