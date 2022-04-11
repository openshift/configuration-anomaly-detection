# Binaries used in Makefile
bin/cobra:
	GOBIN=$(PWD)/bin go install -mod=readonly $(shell go list -m -f '{{ .Path}}/cobra@{{ .Version }}' github.com/spf13/cobra)

bin/embedmd:
	GOBIN=$(PWD)/bin go install -mod=readonly github.com/campoy/embedmd@v1.0.0

bin/golangci-lint:
	GOBIN=$(PWD)/bin go install -mod=readonly github.com/golangci/golangci-lint/cmd/golangci-lint@v1.45.2

bin/gosec:
	GOBIN=$(PWD)/bin go install -mod=readonly github.com/securego/gosec/v2/cmd/gosec@v2.10.0

cadctl/cadctl: cadctl/**/*.go pkg/**/*.go go.mod go.sum
	GOBIN=$(PWD)/cadctl go install -ldflags="-s -w -extldflags=-zrelro -extldflags=-znow" -buildmode=pie -mod=readonly -trimpath $(PWD)/cadctl

# Actions
.DEFAULT_GOAL := all
.PHONY: all
all: build lint test generate-markdown

# build uses the following Go flags:
# -s -w for stripping the binary (making it smaller)
# the extended flags are for enabling ELF hardening features. 
# See also:  https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro
# -mod=readonly and -trimpath are for generating reproducible/verifiable binaries. See also: https://reproducible-builds.org/
# For more information about -buildmode=pie https://www.redhat.com/en/blog/position-independent-executables-pie
.PHONY: build
build: cadctl-install-local-force
	go build -ldflags="-s -w -extldflags=-zrelro -extldflags=-znow" -buildmode=pie -mod=readonly -trimpath ./...

.PHONY: test
test:
	go test -race -mod=readonly ./...

.PHONY: lint
lint: bin/golangci-lint
	GOLANGCI_LINT_CACHE=$(shell mktemp -d) ./bin/golangci-lint run

.PHONY: test-with-race
test-with-race:
	go test -race ./...

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

# pulled from https://github.com/openshift/boilerplate/blob/056cba90733136e589ac2c4cd45238fd6207cfbd/Makefile#L10-L11
.PHONY: isclean
isclean: ## Validate the local checkout is clean. Use ALLOW_DIRTY_CHECKOUT=true to nullify
	@(test "$(ALLOW_DIRTY_CHECKOUT)" != "false" || test 0 -eq $$(git status --porcelain | wc -l)) || (echo "Local git checkout is not clean, commit changes and try again." >&2 && exit 1)

.PHONY: coverage
coverage: hack/codecov.sh


.PHONY: validate
validate: build isclean
