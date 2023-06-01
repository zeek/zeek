#!/bin/bash
#
# Script to batch-delete all untagged images from ECR public repositories,
# defaulting to the zeek/zeek-dev repository.
# First scans for manifest list images that are referencing other images and
# deletes them, then deletes all remaining untagged images.
set -eu

if ! command -v aws >/dev/null; then
    echo "missing aws command" >&2
    exit 1
fi

REGISTRY_ID=${REGISTRY_ID:-103243056077}
REPOSITORY_NAME=${REPOSITORY_NAME:-zeek-dev}
BATCH_DELETE_SIZE=${BATCH_DELETE_SIZE:-50}

# Chunk up "$1" into BATCH_DELETE_SIZE entries and batch-delete them at once
# via aws batch-delete.
#
# Expected input looks as follows to keep things simple:
#
#    imageDigest=sha256:db6...366
#    imageDigest=sha256:2ad...9b0
#
function batch_delete {
    while read -r batch; do
        if [ -z "${batch}" ]; then
            break
        fi

        echo "Deleting ${batch}"
        aws ecr-public batch-delete-image \
            --registry-id "${REGISTRY_ID}" \
            --repository-name "${REPOSITORY_NAME}" \
            --image-ids ${batch}

    done < <(xargs -L ${BATCH_DELETE_SIZE} <<<"$1")
}

# Find all untagged manifest lists with the following media types:
#
#    application/vnd.docker.distribution.manifest.list.v2+json
#    application/vnd.oci.image.index.v1+json
#
# These reference other images, so we need to delete them first as
# otherwise the referenced images can not be deleted.
IMAGE_DIGESTS=$(aws ecr-public describe-images \
    --registry-id "${REGISTRY_ID}" \
    --repository-name "${REPOSITORY_NAME}" \
    --query 'imageDetails[?!imageTags && (contains(imageManifestMediaType, `manifest.list.v2`) || contains(imageManifestMediaType, `image.index.v1`))].{imageDigest: join(`=`, [`imageDigest`, imageDigest])}' \
    --output text)

batch_delete "${IMAGE_DIGESTS}"

# Now find all untagged manifests that are left.
IMAGE_DIGESTS=$(aws ecr-public describe-images \
    --registry-id "${REGISTRY_ID}" \
    --repository-name "${REPOSITORY_NAME}" \
    --query 'imageDetails[?!imageTags].{imageDigest: join(`=`, [`imageDigest`, imageDigest])}' \
    --output text)

batch_delete "${IMAGE_DIGESTS}"
