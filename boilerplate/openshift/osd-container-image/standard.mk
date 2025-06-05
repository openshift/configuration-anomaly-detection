# Validate variables in project.mk exist
IMAGE_REGISTRY?=quay.io
IMAGE_REPOSITORY?=app-sre
REGISTRY_USER?=$(QUAY_USER)
REGISTRY_TOKEN?=$(QUAY_TOKEN)

VERSION_MAJOR?=0
VERSION_MINOR?=1

ifndef IMAGE_NAME
$(error IMAGE_NAME is not set)
endif

### Accommodate docker or podman
#
# The docker/podman creds cache needs to be in a location unique to this
# invocation; otherwise it could collide across jenkins jobs. We'll use
# a .docker folder relative to pwd (the repo root).
CONTAINER_ENGINE_CONFIG_DIR = .docker
# But docker and podman use different options to configure it :eyeroll:
# ==> Podman uses --authfile=PATH *after* the `login` subcommand; but
# also accepts REGISTRY_AUTH_FILE from the env. See
# https://www.mankier.com/1/podman-login#Options---authfile=path
export REGISTRY_AUTH_FILE = ${CONTAINER_ENGINE_CONFIG_DIR}/config.json
# ==> Docker uses --config=PATH *before* (any) subcommand; so we'll glue
# that to the CONTAINER_ENGINE variable itself. (NOTE: I tried half a
# dozen other ways to do this. This was the least ugly one that actually
# works.)
ifndef CONTAINER_ENGINE
CONTAINER_ENGINE=$(shell command -v podman 2>/dev/null || echo docker --config=$(CONTAINER_ENGINE_CONFIG_DIR))
endif

# Generate version and tag information from inputs
COMMIT_NUMBER=$(shell git rev-list `git rev-list --parents HEAD | grep -E "^[a-f0-9]{40}$$"`..HEAD --count)
CURRENT_COMMIT=$(shell git rev-parse --short=7 HEAD)
IMAGE_VERSION := $(VERSION_MAJOR).$(VERSION_MINOR).$(COMMIT_NUMBER)-$(CURRENT_COMMIT)

IMAGE=$(IMAGE_REGISTRY)/$(IMAGE_REPOSITORY)/$(IMAGE_NAME)
IMAGE_TAG=v$(IMAGE_VERSION)
IMAGE_URI?=$(IMAGE):$(IMAGE_TAG)
DOCKERFILE ?=./build/Dockerfile


# Consumer can optionally define ADDITIONAL_IMAGE_SPECS like:
#     define ADDITIONAL_IMAGE_SPECS
#     ./path/to/a/Dockerfile $(IMAGE_REGISTRY)/$(IMAGE_REPOSITORY)/a-image:v1.2.3
#     ./path/to/b/Dockerfile $(IMAGE_REGISTRY)/$(IMAGE_REPOSITORY)/b-image:v4.5.6
#     endef
# Each will be conditionally built and pushed along with the default image.
define IMAGES_TO_BUILD
$(DOCKERFILE) $(IMAGE_URI)
$(ADDITIONAL_IMAGE_SPECS)
endef
export IMAGES_TO_BUILD

REGISTRY_USER ?=
REGISTRY_TOKEN ?=

ALLOW_DIRTY_CHECKOUT?=false

# TODO: Figure out how to discover this dynamically
CONVENTION_DIR := boilerplate/openshift/osd-container-image

# Set the default goal in a way that works for older & newer versions of `make`:
# Older versions (<=3.8.0) will pay attention to the `default` target.
# Newer versions pay attention to .DEFAULT_GOAL, where uunsetting it makes the next defined target the default:
# https://www.gnu.org/software/make/manual/make.html#index-_002eDEFAULT_005fGOAL-_0028define-default-goal_0029
.DEFAULT_GOAL :=
.PHONY: default
default: osd-container-image-build

.PHONY: isclean
isclean:
	@(test "$(ALLOW_DIRTY_CHECKOUT)" != "false" || test 0 -eq $$(git status --porcelain | wc -l)) || (echo "Local git checkout is not clean, commit changes and try again." >&2 && git --no-pager diff && exit 1)

.PHONY: osd-container-image-build
osd-container-image-build: isclean
	${CONTAINER_ENGINE} build --pull -f $(DOCKERFILE) -t $(IMAGE_URI) .

.PHONY: osd-container-image-push
osd-container-image-push: osd-container-image-login osd-container-image-build
	${CONTAINER_ENGINE} push ${IMAGE_URI}

.PHONY: prow-config
prow-config:
	${CONVENTION_DIR}/prow-config ${RELEASE_CLONE}


#########################
# Targets used by app-sre
#########################

.PHONY: osd-container-image-login
osd-container-image-login:
	@test "${REGISTRY_USER}" != "" && test "${REGISTRY_TOKEN}" != "" || (echo "REGISTRY_USER and REGISTRY_TOKEN must be defined" && exit 1)
	mkdir -p ${CONTAINER_ENGINE_CONFIG_DIR}
	@${CONTAINER_ENGINE} login -u="${REGISTRY_USER}" -p="${REGISTRY_TOKEN}" quay.io

# TODO: figure out how to osd-container-image-login only once across multiple `make` calls
.PHONY: osd-container-image-build-push-one
osd-container-image-build-push-one: isclean osd-container-image-login
	@(if [[ -z "${IMAGE_URI}" ]]; then echo "Must specify IMAGE_URI"; exit 1; fi)
	@(if [[ -z "${DOCKERFILE_PATH}" ]]; then echo "Must specify DOCKERFILE_PATH"; exit 1; fi)
	${CONTAINER_ENGINE} build --pull -f $(DOCKERFILE_PATH) -t $(IMAGE_URI) .
	${CONTAINER_ENGINE} push ${IMAGE_URI}

# build-push: Construct, tag, and push all container images.
# TODO: Boilerplate this script.
.PHONY: osd-container-image-build-push
osd-container-image-build-push:
	${CONVENTION_DIR}/app-sre-build-push.sh "$$IMAGES_TO_BUILD"
