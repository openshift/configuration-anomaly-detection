include project.mk
include boilerplate/generated-includes.mk

GOLANGCI_LINT_VERSION=v1.53.3
PRE_COMMIT_HOOK = .git/hooks/pre-commit
PRE_COMMIT_SCRIPT = hack/pre-commit.sh

# Binaries used in Makefile
bin/cobra:
	GOBIN=$(PWD)/bin go install -mod=readonly $(shell go list -m -f '{{ .Path}}/cobra@{{ .Version }}' github.com/spf13/cobra)

bin/embedmd:
	GOBIN=$(PWD)/bin go install -mod=readonly github.com/campoy/embedmd@v1.0.0

bin/gosec:
	GOBIN=$(PWD)/bin go install -mod=readonly github.com/securego/gosec/v2/cmd/gosec@v2.10.0

bin/mockgen:
	GOBIN=$(PWD)/bin go install -mod=readonly github.com/golang/mock/mockgen@v1.6.0

cadctl/cadctl: cadctl/**/*.go pkg/**/*.go go.mod go.sum
	GOBIN=$(PWD)/cadctl go install -ldflags="-s -w" -mod=readonly -trimpath $(PWD)/cadctl

# Installed using instructions from: https://golangci-lint.run/usage/install/#linux-and-windows
getlint:
	@mkdir -p $(GOPATH)/bin
	@ls $(GOPATH)/bin/golangci-lint 1>/dev/null || (echo "Installing golangci-lint..." && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin $(GOLANGCI_LINT_VERSION))

## make all binaries be used before any other commands
# Required as mockgen is running without a relative path
export PATH := $(PWD)/bin:$(PATH)


# Actions
.DEFAULT_GOAL := all
.PHONY: all
all: build lint test generate-markdown pre-commit

# build uses the following Go flags:
# -s -w for stripping the binary (making it smaller)
# -mod=readonly and -trimpath are for generating reproducible/verifiable binaries. See also: https://reproducible-builds.org/
.PHONY: build
build: cadctl-install-local-force
	go build -ldflags="-s -w" -mod=readonly -trimpath ./...

.PHONY: test
test:
	go test -race -mod=readonly ./...

.PHONY: lint
lint: getlint lint-only-hack
	GOLANGCI_LINT_CACHE=$(shell mktemp -d)  $(GOPATH)/bin/golangci-lint run

.PHONY: lint-only-hack
lint-only-hack: getlint
	cd hack/update-template/ && GOLANGCI_LINT_CACHE=$(shell mktemp -d) $(GOPATH)/bin/golangci-lint run -c ../../.golangci.yml

.PHONY: test-with-race
test-with-race:
	go test -race ./...

.PHONY: generate
generate: bin/mockgen generate-template-file generate-markdown
	go generate -mod=readonly ./...

.PHONY: test-with-coverage
test-with-coverage:
	go test -cover -mod=readonly ./...

.PHONY: cadctl-install-local
cadctl-install-local: cadctl/cadctl

.PHONY: cadctl-install-local-force
cadctl-install-local-force:
	rm cadctl/cadctl >/dev/null 2>&1 || true
	make cadctl-install-local

# generate-markdown will update the existing markdown files with the contents of the embededed files.
# -w will write the changes to disk instead of presenting them.
MARKDOWN_SOURCES := $(shell find $(SOURCEDIR) -name '*.md')
.PHONY: generate-markdown
generate-markdown: $(MARKDOWN_SOURCES) bin/embedmd
	./bin/embedmd -w $(MARKDOWN_SOURCES)

## CI actions

.PHONY: coverage
coverage: 
	hack/codecov.sh


.PHONY: generate-template-file
generate-template-file:
	cd ./hack/update-template/ && go build -mod=readonly . && ./update-template

# not using the 'all' target to make the target independent
.PHONY: validate
validate: build generate checks isclean

# will hold all of the checks that will run on the repo. this can be extracted to a script if need be
.PHONY: checks
checks:  check-duplicate-error-messages

# check-duplicate-error-messages will conform with
.PHONY: check-duplicate-error-messages
check-duplicate-error-messages:
	@(test $$(grep -Ir 'fmt.Errorf("' . | grep -v -e './.git' -e .*.md | sed 's/\(.*\)\(fmt.Errorf.*\)/\2/' | sort | uniq -c | awk '$$1 != "1"' | wc -l) -eq 0) || (echo "There are duplicate error values, please consolidate them or make them unique" >&2 && exit 1)

.PHONY: boilerplate-update
boilerplate-update:
	@boilerplate/update

.PHONY: pre-commit
pre-commit:
	@cp $(PRE_COMMIT_SCRIPT) $(PRE_COMMIT_HOOK)
	@chmod +x $(PRE_COMMIT_HOOK)

.PHONY: go-test
go-test:
	go test $(TESTOPTS) -mod=readonly ./...