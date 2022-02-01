# Binaries used in Makefile
bin/cobra:
	GOBIN=$(PWD)/bin go install github.com/spf13/cobra/cobra@v1.3.0

cadctl/cadctl: cadctl/**/*.go pkg/**/*.go go.mod go.sum
	GOBIN=$(PWD)/cadctl go install $(PWD)/cadctl

# Actions
.DEFAULT_GOAL := all
.PHONY: all
all: build test

.PHONY: build
build:
	go build ./...

.PHONY: test
test:
	go test ./...

.PHONY: cadctl-install-local
cadctl-install-local: cadctl/cadctl

## CI actions 

# pulled from https://github.com/openshift/boilerplate/blob/056cba90733136e589ac2c4cd45238fd6207cfbd/Makefile#L10-L11
.PHONY: isclean
isclean: ## Validate the local checkout is clean. Use ALLOW_DIRTY_CHECKOUT=true to nullify
	@(test "$(ALLOW_DIRTY_CHECKOUT)" != "false" || test 0 -eq $$(git status --porcelain | wc -l)) || (echo "Local git checkout is not clean, commit changes and try again." >&2 && exit 1)

# not using the 'all' target to make the target independant
.PHONY: ci-check
ci-check: build test isclean
