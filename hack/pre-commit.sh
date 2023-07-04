#!/usr/bin/env bash

ROOT_DIR=$(git rev-parse --show-toplevel)
GOFILES=$(git diff --cached --name-only --diff-filter=ACM | grep --color=never -E '^.*\.go$')

if [[ ! -z $GOFILES ]]; then
    printf "Running linter...\n\n"
    $GOPATH/bin/golangci-lint run -c $ROOT_DIR/.golangci.yml --fix $ROOT_DIR/...
fi