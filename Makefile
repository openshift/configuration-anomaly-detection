include project.mk
include boilerplate/generated-includes.mk

GOLANGCI_LINT_VERSION=v1.58.1
PRE_COMMIT_HOOK = .git/hooks/pre-commit
PRE_COMMIT_SCRIPT = hack/pre-commit.sh

.DEFAULT_GOAL := all

help:  # Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[0-9A-Za-z_-]+:.*?##/ { printf "  \033[36m%-50s\033[0m %s\n", $$1, $$2 } /^\$$\([0-9A-Za-z_-]+\):.*?##/ { gsub("_","-", $$1); printf "  \033[36m%-50s\033[0m %s\n", tolower(substr($$1, 3, length($$1)-7)), $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Global:
.PHONY: all 
all: interceptor cadctl template-updater generate-template-file  ## Generate, build, lint, test all subprojects

.PHONY: build 
build: build-interceptor build-cadctl build-template-updater ## Build all subprojects in this repository 

.PHONY: lint
lint: getlint lint-cadctl lint-interceptor lint-template-updater ## Lint all subprojects

##@ cadctl:
.PHONY: cadctl 
cadctl: generate-cadctl build-cadctl test-cadctl lint-cadctl generate-template-file ## Run all targets for cadctl (generate, build, test, lint, generation)

.PHONY: generate-cadctl 
generate-cadctl: ## Generate mocks for cadctl
	go generate -mod=readonly ./...

.PHONY: build-cadctl
build-cadctl: ## Build the cadctl binary
	@echo
	@echo "Building cadctl..."
	cd cadctl && go build -ldflags="-s -w" -mod=readonly -trimpath -o ../bin/cadctl .

.PHONY: lint-cadctl 
lint-cadctl: ## Lint cadctl subproject
	@echo
	@echo "Linting cadctl..."
	cd cadctl && GOLANGCI_LINT_CACHE=$$(mktemp -d) $(GOPATH)/bin/golangci-lint run -c ../.golangci.yml

.PHONY: test-cadctl
test-cadctl:  ## Run automated tests for cadctl
	@echo
	@echo "Running unit tests for cadctl..."
	go test $(TESTOPTS) -race -mod=readonly ./cadctl/... ./pkg/...

##@ Interceptor:
.PHONY: interceptor
interceptor: build-interceptor test-interceptor lint-interceptor ## Run all targets for interceptor (build, test, lint)

.PHONY: build-interceptor 
build-interceptor: ## Build the interceptor binary
	@echo
	@echo "Building interceptor..."
	cd interceptor && go build -ldflags="-s -w" -mod=readonly -trimpath -o ../bin/interceptor .

.PHONY: lint-interceptor 
lint-interceptor: ## Lint interceptor subproject
	@echo
	@echo "Linting interceptor..."
	cd interceptor && GOLANGCI_LINT_CACHE=$$(mktemp -d) $(GOPATH)/bin/golangci-lint run -c ../.golangci.yml

.PHONY: test-interceptor 
test-interceptor: build-interceptor ## Run automated tests for interceptor
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
lint-template-updater: ## Lint template-updater subproject
	@echo
	@echo "Linting template-updater..."
	cd hack/update-template && GOLANGCI_LINT_CACHE=$$(mktemp -d) $(GOPATH)/bin/golangci-lint run -c ../../.golangci.yml

##@ Utility:
.PHONY: pre-commit 
pre-commit: ## Run pre-commit hook
	@echo
	@echo "Running pre-commit hook..."
	@cp $(PRE_COMMIT_SCRIPT) $(PRE_COMMIT_HOOK)
	@chmod +x $(PRE_COMMIT_HOOK)

.PHONY: boilerplate-update 
boilerplate-update: ## Update boilerplate version
	@boilerplate/update

.PHONY: generate-template-file
generate-template-file: build-template-updater ## Generate deploy template file
	@echo
	@echo "Generating template file..."
	cp ./bin/template-updater ./hack/update-template/ && cd ./hack/update-template/ && ./template-updater

# Installed using instructions from: https://golangci-lint.run/usage/install/#linux-and-windows
getlint:
	@mkdir -p $(GOPATH)/bin
	@ls $(GOPATH)/bin/golangci-lint 1>/dev/null || (echo "Installing golangci-lint..." && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin $(GOLANGCI_LINT_VERSION))

### CI Only
.PHONY: coverage
coverage:
	hack/codecov.sh

.PHONY: validate
validate: generate-template-file isclean

# Build targets
cadctl/cadctl: cadctl/**/*.go pkg/**/*.go go.mod go.sum
	GOBIN=$(PWD)/cadctl go install -ldflags="-s -w" -mod=readonly -trimpath $(PWD)/cadctl

.PHONY: cadctl-install-local
cadctl-install-local: cadctl/cadctl

.PHONY: cadctl-install-local-force
cadctl-install-local-force:
	rm cadctl/cadctl >/dev/null 2>&1 || true
	make cadctl-install-local
