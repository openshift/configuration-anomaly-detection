#!/usr/bin/env bash
# This shell script is required for the app-sre quay image pipeline.
# The App-SRE pipeline will trigger this script. We can modify the script as we like,
# but the final result should be that we upload a new image to the quay repository.

make test
make validate

IMAGE="quay.io/app-sre/configuration-anomaly-detection"
IMAGE_TAG=$(git rev-parse --short=7 HEAD)

docker build -t "${IMAGE_NAME}:latest" .
docker tag "${IMAGE_NAME}:latest" "${IMAGE_NAME}:${IMAGE_TAG}"

DOCKER_CONF="${PWD}/.docker"
mkdir -p "${DOCKER_CONF}"
docker --config="${DOCKER_CONF}" login -u="${QUAY_USER}" -p="${QUAY_TOKEN}" quay.io

docker --config="${DOCKER_CONF}" push "${IMAGE_NAME}:latest"
docker --config="${DOCKER_CONF}" push "${IMAGE_NAME}:${IMAGE_TAG}"