# Project specific values
OPERATOR_NAME?=configuration-anomaly-detection

E2E_SUITE_IMAGE_REGISTRY?=quay.io
E2E_SUITE_IMAGE_REPOSITORY?=app-sre
E2E_SUITE_IMAGE_NAME?=$(OPERATOR_NAME)-test-

REGISTRY_USER?=$(QUAY_USER)
REGISTRY_TOKEN?=$(QUAY_TOKEN)

######################
# Targets used by e2e test harness
######################

# create binary
.PHONY: e2e-suite-build
e2e-suite-build: GOFLAGS_MOD=-mod=mod
e2e-suite-build: GOENV=GOOS=${GOOS} GOARCH=${GOARCH} CGO_ENABLED=0 GOFLAGS="${GOFLAGS_MOD}"
e2e-suite-build:
	go mod tidy
	${GOENV} go test ./test/e2e -v -c --tags=osde2e -o e2e-suite.test

# TODO: Push to a known image tag and commit id
# push e2e suite image
# Use current commit as e2e suite image tag
CURRENT_COMMIT=$(shell git rev-parse --short=7 HEAD)
E2E_SUITE_IMAGE_TAG=$(CURRENT_COMMIT)

.PHONY: e2e-image-build-push
e2e-image-build-push:
	${CONTAINER_ENGINE} build --pull -f test/e2e/Dockerfile -t $(E2E_SUITE_IMAGE_REGISTRY)/$(E2E_SUITE_IMAGE_REPOSITORY)/$(E2E_SUITE_IMAGE_NAME):$(E2E_SUITE_IMAGE_TAG) .
	${CONTAINER_ENGINE} tag $(E2E_SUITE_IMAGE_REGISTRY)/$(E2E_SUITE_IMAGE_REPOSITORY)/$(E2E_SUITE_IMAGE_NAME):$(E2E_SUITE_IMAGE_TAG) $(E2E_SUITE_IMAGE_REGISTRY)/$(E2E_SUITE_IMAGE_REPOSITORY)/$(E2E_SUITE_IMAGE_NAME):latest
	${CONTAINER_ENGINE} push $(E2E_SUITE_IMAGE_REGISTRY)/$(E2E_SUITE_IMAGE_REPOSITORY)/$(E2E_SUITE_IMAGE_NAME):$(E2E_SUITE_IMAGE_TAG)
	${CONTAINER_ENGINE} push $(E2E_SUITE_IMAGE_REGISTRY)/$(E2E_SUITE_IMAGE_REPOSITORY)/$(E2E_SUITE_IMAGE_NAME):latest