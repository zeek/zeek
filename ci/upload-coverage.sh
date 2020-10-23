#! /usr/bin/env bash

# The ZEEK_COVERALLS_REPO_TOKEN environment variable must exist
# for this script to work correctly. On Cirrus, this is provided
# via the secured variables.

# Only do this on the master branch to avoid having a ton of data
# in Coveralls.
if [ "${CIRRUS_REPO_FULL_NAME}" != "zeek/zeek" ]; then
    echo "Coverage upload skipped for non-zeek repo"
    exit 0
fi

if [ "${CIRRUS_BRANCH}" != "master" ]; then
    echo "Coverage upload skipped for non-master branches"
    exit 0
fi

cd testing/coverage
make coverage
make coveralls
