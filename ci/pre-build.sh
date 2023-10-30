#/usr/bin/env bash
#
# If ZEEK_CI_PREBUILD_COMMAND is not empty, execute it via bash -c. That's it.
set -ex

if [ -n "$ZEEK_CI_PREBUILD_COMMAND" ]; then
    bash -c "$ZEEK_CI_PREBUILD_COMMAND"
fi
