#!/usr/bin/env bash

make osd-container-image-build-push

# Generate version and tag information from inputs
COMMIT_NUMBER=$(git rev-list `git rev-list --parents HEAD | egrep "^[a-f0-9]{40}$$"`..HEAD --count)
CURRENT_COMMIT=$(git rev-parse --short=7 HEAD)
IMAGE_TAG="v0.1.${COMMIT_NUMBER}-${CURRENT_COMMIT}"

docker tag quay.io/app-sre/configuration-anomaly-detection:${IMAGE_TAG} quay.io/app-sre/configuration-anomaly-detection:${CURRENT_COMMIT}
docker push quay.io/app-sre/configuration-anomaly-detection:${CURRENT_COMMIT}