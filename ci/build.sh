#! /usr/bin/env bash

set -e
set -x

# If we're on macOS, use --osx-sysroot to ensure we can find the SDKs from Xcode. This avoids
# some problems with Catalina specifically, but it doesn't break anything on Big Sur either.
if [ "${CIRRUS_OS}" == "darwin" ]; then
    export ZEEK_CI_CONFIGURE_FLAGS="${ZEEK_CI_CONFIGURE_FLAGS} --osx-sysroot=$(xcrun --show-sdk-path)"
fi

if [ "${ZEEK_CI_CREATE_ARTIFACT}" != "1" ]; then
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
