#!/bin/bash
#
# This script expects two images in the local container registry:
#
#   zeek/zeek-multiarch:arm64
#   zeek/zeek-multiarch:amd64
#
# It retags these according to the environment variables IMAGE_NAME and
# IMAGE_TAG as zeek/${IMAGE_NAME}:${IMAGE_TAG}-{arm64,amd64}, pushes them
# to the registry, then creates a manifest as zeek/${IMAGE_NAME}:${IMAGE_TAG}
# containing the arch specific tags and pushes it.
#
# REGISTRY_PREFIX can be used to prefix images with a registry. Needs
# to end with a slash.
#
set -eux

REGISTRY_PREFIX=${REGISTRY_PREFIX:-}
ZEEK_IMAGE_REPO=${ZEEK_IMAGE_REPO:-zeek}

ADDITIONAL_MANIFEST_TAGS=${ADDITIONAL_MANIFEST_TAGS:-}

# Check for ending slash in registry prefix
if [ -n "${REGISTRY_PREFIX}" ]; then
    if [[ ! "${REGISTRY_PREFIX}" =~ .+/$ ]]; then
        echo "Missing slash in: ${REGISTRY_PREFIX}"
        exit 1
    fi
fi

# Forward arguments to docker and retry the command once if failing (e.g network issues).
function do_docker {
    if ! docker "$@"; then
        echo "docker invocation failed. retrying in 5 seconds." >&2
        sleep 5
        docker "$@"
    fi
}

function create_and_push_manifest {
    # Expects $1 to be the manifest tag, globals otherwise
    do_docker manifest create --amend ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${1} \
        ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}-arm64 \
        ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}-amd64

    do_docker manifest push ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/$IMAGE_NAME:${1}
}

do_docker tag zeek/zeek-multiarch:arm64 ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}-arm64
do_docker tag zeek/zeek-multiarch:amd64 ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}-amd64
do_docker push ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}-arm64
do_docker push ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}-amd64

create_and_push_manifest ${IMAGE_TAG}

if [ -n "${ADDITIONAL_MANIFEST_TAGS}" ]; then
    # Rely on default IFS splitting on space
    for tag in ${ADDITIONAL_MANIFEST_TAGS}; do
        create_and_push_manifest ${tag}
    done
fi
