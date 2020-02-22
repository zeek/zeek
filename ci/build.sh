#! /usr/bin/env bash

set -e
set -x

./configure ${ZEEK_CI_CONFIGURE_FLAGS}
make -j ${ZEEK_CI_CPUS}
