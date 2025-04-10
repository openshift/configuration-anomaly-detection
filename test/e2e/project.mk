# Project specific values
OPERATOR_NAME?=configuration-anomaly-detection

HARNESS_IMAGE_REGISTRY?=quay.io
HARNESS_IMAGE_REPOSITORY?=app-sre
HARNESS_IMAGE_NAME?=$(OPERATOR_NAME)-test-harness

REGISTRY_USER?=$(QUAY_USER)
REGISTRY_TOKEN?=$(QUAY_TOKEN)

######################
# Targets used by e2e test harness
######################

# create binary
.PHONY: e2e-harness-build
e2e-harness-build: GOFLAGS_MOD=-mod=mod
e2e-harness-build: GOENV=GOOS=${GOOS} GOARCH=${GOARCH} CGO_ENABLED=0 GOFLAGS="${GOFLAGS_MOD}"
e2e-harness-build:
	go mod tidy
	${GOENV} go test ./test/e2e -v -c --tags=osde2e -o harness.test

# TODO: Push to a known image tag and commit id
# push harness image
# Use current commit as harness image tag
CURRENT_COMMIT=$(shell git rev-parse --short=7 HEAD)
HARNESS_IMAGE_TAG=$(CURRENT_COMMIT)

.PHONY: e2e-image-build-push
e2e-image-build-push:
	${CONTAINER_ENGINE} build --pull -f test/e2e/Dockerfile -t $(HARNESS_IMAGE_REGISTRY)/$(HARNESS_IMAGE_REPOSITORY)/$(HARNESS_IMAGE_NAME):$(HARNESS_IMAGE_TAG) .
	${CONTAINER_ENGINE} tag $(HARNESS_IMAGE_REGISTRY)/$(HARNESS_IMAGE_REPOSITORY)/$(HARNESS_IMAGE_NAME):$(HARNESS_IMAGE_TAG) $(HARNESS_IMAGE_REGISTRY)/$(HARNESS_IMAGE_REPOSITORY)/$(HARNESS_IMAGE_NAME):latest
	${CONTAINER_ENGINE} push $(HARNESS_IMAGE_REGISTRY)/$(HARNESS_IMAGE_REPOSITORY)/$(HARNESS_IMAGE_NAME):$(HARNESS_IMAGE_TAG)
	${CONTAINER_ENGINE} push $(HARNESS_IMAGE_REGISTRY)/$(HARNESS_IMAGE_REPOSITORY)/$(HARNESS_IMAGE_NAME):latest