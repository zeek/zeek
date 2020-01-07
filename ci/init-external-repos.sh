#! /usr/bin/env bash

function banner
    {
    local msg="${1}"
    printf "+--------------------------------------------------------------+\n"
    printf "| %-60s |\n" "$(date)"
    printf "| %-60s |\n" "${msg}"
    printf "+--------------------------------------------------------------+\n"
    }

set -e

cd testing/external
[[ ! -d zeek-testing ]] && make init
cd zeek-testing
git checkout -q $(cat ../commit-hash.zeek-testing)

if [[ -n "${CIRRUS_CI}" ]]; then
    if [[ -d ../zeek-testing-traces ]]; then
        banner "Use existing/cached zeek-testing traces"
    else
        banner "Create cache directory for zeek-testing traces"
        mkdir ../zeek-testing-traces
    fi

    rm -rf Traces
    ln -s ../zeek-testing-traces Traces
fi

make update-traces
cd ..

# Note that this script is also called when populating the public cache, so
# the zeek-testing-private dir could have been created/populated already.
if [[ -n "${CIRRUS_CI}" ]] && [[ ! -d zeek-testing-private ]]; then
    # If we're running this on Cirrus, the SSH key won't be available to PRs,
    # so don't make any of this fail the task in that case.  (But technically,
    # the key is also available in PRs for people with write access to the
    # repo, so we can still try for those cases).
    if [[ -n "${CIRRUS_PR}" ]]; then
        set +e
    else
        set -e
    fi

    banner "Trying to clone zeek-testing-private git repo"
    echo "${ZEEK_TESTING_PRIVATE_SSH_KEY}" > cirrus_key.b64
    base64 --decode cirrus_key.b64 > cirrus_key
    rm cirrus_key.b64
    chmod 600 cirrus_key
    git --version
    # Note: GIT_SSH_COMMAND requires git 2.3.0+
    export GIT_SSH_COMMAND="ssh -i cirrus_key -F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
    git clone git@github.com:zeek/zeek-testing-private
    rm cirrus_key
fi

set -e

if [[ -d zeek-testing-private ]]; then
    # Note that we never cache private pcaps.
    banner "Update zeek-testing-private traces"
    cd zeek-testing-private
    make update-traces
fi
