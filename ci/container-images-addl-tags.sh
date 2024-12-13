#!/bin/bash
#
# This script produces output in the form of
#
#     $ REMOTE=awelzel ./ci/container-images-addl-tags.sh v7.0.5
#     ADDITIONAL_MANIFEST_TAGS= lts 7.0 latest
#
# This scripts expects visibility to all tags and release branches
# to work correctly. See the find-current-version.sh for details.
set -eu

dir="$(cd "$(dirname "$0")" && pwd)"

if [ $# -ne 1 ] || [ -z "${1}" ]; then
    echo "Usage: $0 <tag>" >&2
    exit 1
fi

TAG="${1}"

# Find current versions for lts and feature depending on branches and
# tags in the repo. sed for escaping the dot in the version for using
# it in the regex below to match against TAG.
lts_ver=$(${dir}/find-current-version.sh lts)
lts_pat="^v$(echo $lts_ver | sed 's,\.,\\.,g')\.[0-9]+\$"
feature_ver=$(${dir}/find-current-version.sh feature)
feature_pat="^v$(echo $feature_ver | sed 's,\.,\\.,g')\.[0-9]+\$"

# Construct additional tags for the image. At most this will
# be "lts x.0 feature" for an lts branch x.0 that is currently
# also the latest feature branch.
ADDL_MANIFEST_TAGS=
if echo "${TAG}" | grep -q -E "${lts_pat}"; then
    ADDL_MANIFEST_TAGS="${ADDL_MANIFEST_TAGS} lts ${lts_ver}"
fi

if echo "${TAG}" | grep -q -E "${feature_pat}"; then
    ADDL_MANIFEST_TAGS="${ADDL_MANIFEST_TAGS} latest"
    if [ "${feature_ver}" != "${lts_ver}" ]; then
        ADDL_MANIFEST_TAGS="${ADDL_MANIFEST_TAGS} ${feature_ver}"
    fi
fi

echo "ADDITIONAL_MANIFEST_TAGS=${ADDL_MANIFEST_TAGS}"
