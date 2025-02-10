IMAGE_REGISTRY?=quay.io
IMAGE_REPOSITORY?=app-sre
IMAGE_NAME?=configuration-anomaly-detection
DOCKERFILE?=./build/Dockerfile
define ADDITIONAL_IMAGE_SPECS
./build/Dockerfile $(IMAGE_REGISTRY)/$(IMAGE_REPOSITORY)/$(IMAGE_NAME):$(CURRENT_COMMIT)
endef

include boilerplate/generated-includes.mk

GOLANGCI_LINT_VERSION=v1.59.1
MOCKGEN_VERSION=v0.5.0

.DEFAULT_GOAL := all

help:  # Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[0-9A-Za-z_-]+:.*?##/ { printf "  \033[36m%-50s\033[0m %s\n", $$1, $$2 } /^\$$\([0-9A-Za-z_-]+\):.*?##/ { gsub("_","-", $$1); printf "  \033[36m%-50s\033[0m %s\n", tolower(substr($$1, 3, length($$1)-7)), $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Global:
.PHONY: all
all: interceptor cadctl template-updater generate-template-file  ## Generate, build, lint, test all subprojects

.PHONY: build
build: build-interceptor build-cadctl build-template-updater ## Build all subprojects in this repository

.PHONY: lint
lint: lint-cadctl lint-interceptor lint-template-updater ## Lint all subprojects

##@ cadctl:
.PHONY: cadctl
cadctl: generate-cadctl build-cadctl test-cadctl lint-cadctl generate-template-file ## Run all targets for cadctl (generate, build, test, lint, generation)

.PHONY: generate-cadctl
generate-cadctl: check-go121-install install-mockgen ## Generate mocks for cadctl
	go generate -mod=readonly ./...

.PHONY: build-cadctl
build-cadctl: check-go121-install ## Build the cadctl binary
	@echo
	@echo "Building cadctl..."
	cd cadctl && go build -ldflags="-s -w" -mod=readonly -trimpath -o ../bin/cadctl .

.PHONY: lint-cadctl
lint-cadctl: install-linter ## Lint cadctl subproject
	@echo
	@echo "Linting cadctl..."
	GOLANGCI_LINT_CACHE=$$(mktemp -d) $(GOPATH)/bin/golangci-lint run -c .golangci.yml

.PHONY: test-cadctl
test-cadctl: check-go121-install ## Run automated tests for cadctl
	@echo
	@echo "Running unit tests for cadctl..."
	go test $(TESTOPTS) -race -mod=readonly ./cadctl/... ./pkg/...

##@ Interceptor:
.PHONY: interceptor
interceptor: build-interceptor test-interceptor lint-interceptor ## Run all targets for interceptor (build, test, lint)

.PHONY: build-interceptor
build-interceptor: check-go121-install ## Build the interceptor binary
	@echo
	@echo "Building interceptor..."
	cd interceptor && go build -ldflags="-s -w" -mod=readonly -trimpath -o ../bin/interceptor .

.PHONY: lint-interceptor
lint-interceptor: install-linter ## Lint interceptor subproject
	@echo
	@echo "Linting interceptor..."
	cd interceptor && GOLANGCI_LINT_CACHE=$$(mktemp -d) $(GOPATH)/bin/golangci-lint run -c ../.golangci.yml

.PHONY: test-interceptor
test-interceptor: check-go121-install check-jq-install check-vault-install build-interceptor ## Run automated tests for interceptor
	@echo
	@echo "Running unit tests for interceptor..."
	cd interceptor && go test -race -mod=readonly ./...
	@echo
	@echo "Running e2e tests for interceptor..."
	cd interceptor && ./test/e2e.sh

##@ Template-updater:
.PHONY: template-updater
template-updater: build-template-updater lint-template-updater ## Run all targets for template-updater

.PHONY: build-template-updater
build-template-updater: ## Build the template-updater binary
	@echo
	@echo "Building template-updater..."
	cd hack/update-template && go build -ldflags="-s -w" -mod=readonly -trimpath -o ../../bin/template-updater .

.PHONY: lint-template-updater
lint-template-updater: install-linter ## Lint template-updater subproject
	@echo
	@echo "Linting template-updater..."
	cd hack/update-template && GOLANGCI_LINT_CACHE=$$(mktemp -d) $(GOPATH)/bin/golangci-lint run -c ../../.golangci.yml

.PHONY: boilerplate-update
boilerplate-update: ## Update boilerplate version
	@boilerplate/update

.PHONY: generate-template-file
generate-template-file: build-template-updater ## Generate deploy template file
	@echo
	@echo "Generating template file..."
	cp ./bin/template-updater ./hack/update-template/ && cd ./hack/update-template/ && ./template-updater

### CI Only
.PHONY: coverage
coverage:
	hack/codecov.sh

.PHONY: validate
validate: generate-template-file isclean

### Prerequisites
### It is assumed that 'make' is already installed
### Version of go is checked but the version the tools are not checked as this should not matter much.
.PHONY: check-%-install
check-%-install:
	@type $* 1> /dev/null || (>&2 echo && echo "'$*' IS NOT INSTALLED - install it manually" && echo && false)

.PHONY: check-go121-install
check-go121-install:
	@(type go 1> /dev/null && go version | grep -q 'go[1-9].[2-9][1-9]') || (>&2 echo && echo "'go' WITH VERSION >= 1.21 IS NOT INSTALLED - install it manually" && echo && false)

.PHONY: install-linter
install-linter: check-curl-install check-go121-install
	@ls $(GOPATH)/bin/golangci-lint 1>/dev/null || (echo && echo "Installing 'golangci-lint'..." && mkdir -p $(GOPATH)/bin && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin $(GOLANGCI_LINT_VERSION))

.PHONY: install-mockgen
install-mockgen: check-go121-install
	@type mockgen 1> /dev/null || (echo && echo "Installing 'mockgen'..." && go install go.uber.org/mock/mockgen@$(MOCKGEN_VERSION))
