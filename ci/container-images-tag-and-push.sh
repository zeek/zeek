#!/bin/bash
#
# This script expects two local images in the local container registry:
#
#   zeek/zeek-multiarch:arm64
#   zeek/zeek-multiarch:amd64
#
# It retags these according to the environment ARCH_IMAGE_NAME and
# ARCH_IMAGE_TAG as zeek/${ARCH_IMAGE_NAME}:${ARCH_IMAGE_TAG}-{arm64,amd64},
# pushes them to the registry, then creates a manifest based on MANIFEST_NAME
# and MANIFEST_TAG environment variables as zeek/${MANIFEST_NAME}:${MANIFEST_TAG}
# including the two tags.
#
# REGISTRY_PREFIX can be used to prefix images with a registry. Needs
# to end with a slash.
set -eux

REGISTRY_PREFIX=${REGISTRY_PREFIX:-}
ZEEK_IMAGE_REPO=${ZEEK_IMAGE_REPO:-zeek}

# Check for ending slash in registry prefix
if [ -n "${REGISTRY_PREFIX}" ]; then
    if [[ ! "${REGISTRY_PREFIX}" =~ .+/$ ]]; then
        echo "Missing slash in: ${REGISTRY_PREFIX}"
        exit 1
    fi
fi

docker tag ${ZEEK_IMAGE_REPO}/zeek-multiarch:arm64 ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${ARCH_IMAGE_NAME}:${ARCH_IMAGE_TAG}-arm64
docker tag ${ZEEK_IMAGE_REPO}/zeek-multiarch:amd64 ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${ARCH_IMAGE_NAME}:${ARCH_IMAGE_TAG}-amd64
docker push ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${ARCH_IMAGE_NAME}:${ARCH_IMAGE_TAG}-arm64
docker push ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${ARCH_IMAGE_NAME}:${ARCH_IMAGE_TAG}-amd64

docker manifest create ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/$MANIFEST_NAME:${MANIFEST_TAG} \
    ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${ARCH_IMAGE_NAME}:${ARCH_IMAGE_TAG}-arm64 \
    ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${ARCH_IMAGE_NAME}:${ARCH_IMAGE_TAG}-amd64

docker manifest push ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/$MANIFEST_NAME:${MANIFEST_TAG}
