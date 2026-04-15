#!/bin/bash
# Run btests on Windows with retry logic for flaky tests.

set -o pipefail

export MSYS=disable_pcon

BTEST="python ../../auxil/btest/btest"
JOBS=${ZEEK_CI_CPUS:-8}
RETRIES=${ZEEK_CI_BTEST_RETRIES:-3}

${BTEST} -z ${RETRIES} -j ${JOBS} -d -x btest-results.xml
result=$?

if [ ${result} -ne 0 ] && [ -f .btest.failed.dat ]; then
    echo "=== Initial btest run had failures, retrying after cleanup ==="

    # Convert dot-notation test names (e.g. supervisor.output-redirect-windows)
    # to actual file paths (e.g. supervisor/output-redirect-windows.zeek).
    failed_tests=""
    while IFS= read -r test_name; do
        test_name="${test_name%$'\r'}"
        [ -z "${test_name}" ] && continue
        # Replace dots with directory separators.
        test_path="${test_name//.//}"
        # Find the actual file regardless of extension.
        match=$(ls ${test_path}.* 2>/dev/null | head -1)
        if [ -n "${match}" ]; then
            failed_tests="${failed_tests} ${match}"
        else
            echo "Warning: could not resolve test '${test_name}' to a file"
        fi
    done <.btest.failed.dat

    if [ -z "${failed_tests}" ]; then
        echo "No failed tests could be resolved, skipping retry"
        exit ${result}
    fi

    # Kill lingering python and zeek processes from the test run.
    taskkill //F //IM python.exe 2>/dev/null || true
    taskkill //F //IM zeek.exe 2>/dev/null || true

    # Clear temporary test artifacts.
    rm -rf .tmp

    # Rerun only the failed tests.
    echo "Retrying:${failed_tests}"
    ${BTEST} -z ${RETRIES} -j ${JOBS} -d -x btest-results.xml ${failed_tests}
    result=$?

    if [ ${result} -ne 0 ] && [ -f .btest.failed.dat ]; then
        echo ""
        echo "=== Tests still failing after retry ==="
        cat .btest.failed.dat
        echo "======================================="
    fi
fi

# Collect artifacts for CI (matching Linux ci/test.sh behavior).
if [ -d .tmp ]; then
    rm -rf .tmp/script-coverage
    tar -czf tmp.tar.gz .tmp 2>/dev/null || true
fi

exit ${result}
