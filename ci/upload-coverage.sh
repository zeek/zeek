#! /usr/bin/env bash

# The ZEEK_COVERALLS_REPO_TOKEN environment variable must exist for this script to work
# correctly. On Circle, this is provided via the Zeek context.

# Only do this on the master branch to avoid having a ton of data in Coveralls.
if [ ${ZEEK_IS_INTERNAL_JOB} -ne 1 ]; then
    echo "Coverage upload skipped for jobs from forks"
    exit 0
fi

cd testing/coverage
make coverage
make coveralls
