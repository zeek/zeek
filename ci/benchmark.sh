#! /usr/bin/env bash

ZEEK_BENCHMARK_ENDPOINT="/zeek"

# Setting this causes any command failures to immediately cause the script to fail.
set -e

# Skip running benchmarks for jobs from forks.
if [ ${ZEEK_IS_INTERNAL_JOB:-0} -ne 1 ]; then
    echo "Benchmarking skipped for jobs from forks"
    exit 0
fi

# Something like https://output.circle-artifacts.com/output/job/597ae3bd-be02-4fe2-8e83-0c0ea5aeaa17/artifacts/0/install.tgz
BUILD_URL="https://output.circle-artifacts.com/output/job/${CIRCLE_WORKFLOW_JOB_ID}/artifacts/0/install.tgz"

# Generate an md5 hash of the build file. We can do this here because the path to the
# file still exists from the prior scripts.
BUILD_HASH=$(sha256sum ${ZEEK_CI_WORKING_DIR}/install.tgz | awk '{print $1}')

# Generate an HMAC digest for the path plus a timestamp to send as an authentication
# header. Openssl outputs a hex string here so there's no need to base64 encode it.
TIMESTAMP=$(date -u +'%s')
HMAC_DIGEST=$(echo "${ZEEK_BENCHMARK_ENDPOINT}-${TIMESTAMP}-${BUILD_HASH}" | openssl dgst -sha256 -hmac ${ZEEK_BENCHMARK_HMAC_KEY} | awk '{print $2}')

TARGET="https://${ZEEK_BENCHMARK_HOST}:${ZEEK_BENCHMARK_PORT}${ZEEK_BENCHMARK_ENDPOINT}"

# Turn this back off because we want to be able to capture the output from curl if
# it fails.
set +e

# Make a request to the benchmark host.
curl -sS -G --stderr - --fail --insecure -X POST \
    -o "${ZEEK_CI_WORKING_DIR}/benchmark-${TIMESTAMP}.log" \
    -H "Zeek-HMAC: ${HMAC_DIGEST}" \
    -H "Zeek-HMAC-Timestamp: ${TIMESTAMP}" \
    --data-urlencode "branch=${CIRCLE_BRANCH}" \
    --data-urlencode "build=${BUILD_URL}" \
    --data-urlencode "build_hash=${BUILD_HASH}" \
    --data-urlencode "commit=${CIRCLE_SHA1}" \
    --data-urlencode "cirrus_repo_owner=${CIRCLE_PROJECT_USERNAME}" \
    --data-urlencode "cirrus_repo_name=${CIRCLE_PROJECT_REPONAME}" \
    --data-urlencode "cirrus_task_id=${CIRCLE_WORKFLOW_ID}" \
    --data-urlencode "cirrus_task_name=${CIRCLE_WORKFLOW_JOB_ID}" \
    --data-urlencode "cirrus_build_id=${CIRRUS_BUILD_NUM}" \
    --data-urlencode "cirrus_pr=${CIRCLE_PR_NUMBER}" \
    --data-urlencode "repo_version=$(cat ./VERSION)" \
    "${TARGET}"

STATUS=$?

# If we got a bad status back from the host, we want to make sure to mask the host
# and port from the output.
if [ $STATUS -ne 0 ]; then
    cat ${ZEEK_CI_WORKING_DIR}/benchmark-${TIMESTAMP}.log | sed "s/${ZEEK_BENCHMARK_HOST}/<secret>/g" | sed "s/:${ZEEK_BENCHMARK_PORT}/:<secret>/g"
else
    cat ${ZEEK_CI_WORKING_DIR}/benchmark-${TIMESTAMP}.log
fi

exit $STATUS
