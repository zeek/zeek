#! /usr/bin/env bash

# It's possible to use this script locally from the zeek repo's root dir.
# The parallelism level when running tests locally is $1 if provided, else
# the value of `nproc` if available, otherwise just a single core.

result=0
BTEST=$(pwd)/auxil/btest/btest

# Due to issues with DNS lookups on macOS, one of the Cirrus support people recommended we
# run our tests as root. See https://github.com/cirruslabs/cirrus-ci-docs/issues/1302 for
# more details.
if [[ "${CIRRUS_OS}" == "darwin" ]]; then
    BTEST="sudo ${BTEST}"
fi

if [[ -z "${CIRRUS_CI}" ]]; then
    # Set default values to use in place of env. variables set by Cirrus CI.
    ZEEK_CI_CPUS=1
    [[ $(which nproc) ]] && ZEEK_CI_CPUS=$(nproc)
    [[ -n "${1}" ]] && ZEEK_CI_CPUS=${1}
    ZEEK_CI_BTEST_JOBS=${ZEEK_CI_CPUS}
    ZEEK_CI_BTEST_RETRIES=2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
. ${SCRIPT_DIR}/common.sh

if [ -n "${ZEEK_TSAN_OPTIONS}" ]; then
    export TSAN_OPTIONS=${ZEEK_TSAN_OPTIONS}
fi

if [ -n "${ZEEK_TEST_ULIMIT_OPEN_FILES}" ]; then
    if ! ulimit -n "${ZEEK_TEST_ULIMIT_OPEN_FILES}"; then
        echo "failed to run ulimit -n ${ZEEK_TEST_ULIMIT_OPEN_FILES}" >&2
        exit 1
    fi
fi

function pushd {
    command pushd "$@" >/dev/null || exit 1
}

function popd {
    command popd "$@" >/dev/null || exit 1
}

function banner {
    local msg="${1}"
    printf "+--------------------------------------------------------------+\n"
    printf "| %-60s |\n" "$(date)"
    printf "| %-60s |\n" "${msg}"
    printf "+--------------------------------------------------------------+\n"
}

function run_unit_tests {
    if [[ ${ZEEK_CI_SKIP_UNIT_TESTS} -eq 1 ]]; then
        printf "Skipping unit tests as requested by task configuration\n\n"
        return 0
    fi

    banner "Running unit tests"

    pushd build
    (. ./zeek-path-dev.sh && TZ=UTC zeek --test --no-skip) || result=1
    popd
    return 0
}

function prep_artifacts {
    banner "Prepare artifacts"
    [[ -d .tmp ]] && rm -rf .tmp/script-coverage && tar -czf tmp.tar.gz .tmp
    junit2html btest-results.xml btest-results.html
}

function run_btests {
    banner "Running baseline tests: zeek"

    pushd testing/btest

    ZEEK_PROFILER_FILE=$(pwd)/.tmp/script-coverage/XXXXXX \
        ${BTEST} -z ${ZEEK_CI_BTEST_RETRIES} -d -A -x btest-results.xml -j ${ZEEK_CI_BTEST_JOBS} ${ZEEK_CI_BTEST_EXTRA_ARGS} || result=1
    make coverage
    prep_artifacts
    popd
    return 0
}

function run_external_btests {
    if [[ ${ZEEK_CI_SKIP_EXTERNAL_BTESTS} -eq 1 ]]; then
        printf "Skipping external tests as requested by task configuration\n\n"
        return 0
    fi

    local zeek_testing_pid=""
    local zeek_testing_pid_private=""
    pushd testing/external/zeek-testing
    ZEEK_PROFILER_FILE=$(pwd)/.tmp/script-coverage/XXXXXX \
        ${BTEST} -d -A -x btest-results.xml -j ${ZEEK_CI_BTEST_JOBS} ${ZEEK_CI_BTEST_EXTRA_ARGS} >btest.out 2>&1 &
    zeek_testing_pid=$!
    popd

    if [[ -d testing/external/zeek-testing-private ]]; then
        pushd testing/external/zeek-testing-private
        # Note that we don't use btest's "-d" flag or generate/upload any
        # artifacts to prevent leaking information about the private pcaps.
        ZEEK_PROFILER_FILE=$(pwd)/.tmp/script-coverage/XXXXXX \
            ${BTEST} -A -j ${ZEEK_CI_BTEST_JOBS} >btest.out 2>&1 &
        zeek_testing_private_pid=$!
        popd
    fi

    banner "Running baseline tests: external/zeek-testing"
    wait ${zeek_testing_pid} || result=1
    pushd testing/external/zeek-testing
    cat btest.out
    make coverage
    prep_artifacts
    popd

    if [[ -n "${zeek_testing_private_pid}" ]]; then
        banner "Running baseline tests: external/zeek-testing-private"
        wait ${zeek_testing_private_pid} || result=1
        pushd testing/external/zeek-testing-private
        make coverage
        cat btest.out
        popd
    else
        banner "Skipping private tests (not available for PRs)"
    fi
}

banner "Start tests: ${ZEEK_CI_CPUS} cpus, ${ZEEK_CI_BTEST_JOBS} btest jobs"

run_unit_tests
run_btests
run_external_btests

exit ${result}
