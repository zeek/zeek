#/usr/bin/env bash
#
# If ZEEK_CI_PREBUILD_COMMAND is not empty, execute it via bash -c. That's it.
set -ex

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
"${SCRIPT_DIR}/install-rust-toolchain.sh"

if [ -n "$ZEEK_CI_PREBUILD_COMMAND" ]; then
    bash -c "$ZEEK_CI_PREBUILD_COMMAND"
fi
