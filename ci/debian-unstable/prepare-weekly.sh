#!/bin/sh

apt update
apt dist-upgrade -y

LATEST_VERSION=$(apt-cache search ${ZEEK_CI_COMPILER} |
    awk '/^'"${ZEEK_CI_COMPILER}"'-[0-9]{2}[^-]/ {print $1}' |
    sort | tail -1 | awk -F- '{print $2}')

echo "Installing ${ZEEK_CI_COMPILER} ${LATEST_VERSION}"

apt install -y "${ZEEK_CI_COMPILER}-${LATEST_VERSION}"

if [ "${ZEEK_CI_COMPILER}" = "gcc" ]; then
    apt install -y "g++-${LATEST_VERSION}"
fi

update-alternatives --install /usr/bin/cc cc "/usr/bin/${ZEEK_CI_COMPILER}-${LATEST_VERSION}" 100
update-alternatives --set cc "/usr/bin/${ZEEK_CI_COMPILER}-${LATEST_VERSION}"

if [ "${ZEEK_CI_COMPILER}" = "gcc" ]; then
    update-alternatives --install /usr/bin/c++ c++ "/usr/bin/g++-${LATEST_VERSION}" 100
    update-alternatives --set c++ "/usr/bin/g++-${LATEST_VERSION}"
else
    update-alternatives --install /usr/bin/c++ c++ "/usr/bin/clang++-${LATEST_VERSION}" 100
    update-alternatives --set c++ "/usr/bin/clang++-${LATEST_VERSION}"
fi
