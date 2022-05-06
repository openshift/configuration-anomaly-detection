#!/usr/bin/env bash

set -ev

usage() {
    cat <<EOF
    Usage: $0 "IMAGE_SPECS"
    IMAGE_SPECS is a multiline string where each line has the format:

dockerfile_path image_uri

    For example:

# This is the main operator image
./build/Dockerfile quay.io/app-sre/my-wizbang-operator:v0.1.123-abcd123

# A supplemental image to also build and push
./build/Dockerfile.other quay.io/app-sre/supplemental-image:v5.6.0

    The parameter is mandatory; if only building the catalog image,
    specify the empty string.
EOF
    exit -1
}

REPO_ROOT=$(git rev-parse --show-toplevel)
source $REPO_ROOT/boilerplate/_lib/common.sh

[[ $# -eq 1 ]] || usage

IMAGE_SPECS="$1"

while read dockerfile_path image_uri junk; do
    # Support comment lines
    if [[ "$dockerfile_path" == '#'* ]]; then
        continue
    fi
    # Support blank lines
    if [[ "$dockerfile_path" == "" ]]; then
        continue
    fi
    if [[ "$junk" != "" ]] && [[ "$junk" != '#'* ]]; then
        echo "Invalid image spec: found extra garbage: '$junk'"
        exit 1
    fi
    if ! [[ -f "$dockerfile_path" ]]; then
        echo "Invalid image spec: no such dockerfile: '$dockerfile_path'"
        exit 1
    fi
    # TODO: Validate ${image_uri} format?

    # Don't rebuild the image if it already exists in the repository
    if image_exists_in_repo "${image_uri}"; then
        echo "Skipping build/push for ${image_uri}"
    else
        # build and push the image
        make IMAGE_URI="${image_uri}" DOCKERFILE_PATH="${dockerfile_path}" osd-container-image-build-push-one
    fi
done <<< "$1"
