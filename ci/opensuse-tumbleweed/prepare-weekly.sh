#!/bin/sh

zypper refresh
zypper patch -y --with-update --with-optional

LATEST_VERSION=$(zypper search -n ${ZEEK_CI_COMPILER} |
    awk -F "|" "match(\$2, / ${ZEEK_CI_COMPILER}([0-9]{2})[^-]/, a) {print a[1]}" |
    sort | tail -1)

echo "Installing ${ZEEK_CI_COMPILER} ${LATEST_VERSION}"

zypper install -y "${ZEEK_CI_COMPILER}${LATEST_VERSION}"

if [ "${ZEEK_CI_COMPILER}" == "gcc" ]; then
    zypper install -y "${ZEEK_CI_COMPILER}${LATEST_VERSION}-c++"
fi

update-alternatives --install /usr/bin/cc cc "/usr/bin/${ZEEK_CI_COMPILER}-${LATEST_VERSION}" 100
update-alternatives --set cc "/usr/bin/${ZEEK_CI_COMPILER}-${LATEST_VERSION}"

if [ "${ZEEK_CI_COMPILER}" == "gcc" ]; then
    update-alternatives --install /usr/bin/c++ c++ "/usr/bin/g++-${LATEST_VERSION}" 100
    update-alternatives --set c++ "/usr/bin/g++-${LATEST_VERSION}"
else
    update-alternatives --install /usr/bin/c++ c++ "/usr/bin/clang++-${LATEST_VERSION}" 100
    update-alternatives --set c++ "/usr/bin/clang++-${LATEST_VERSION}"
fi
