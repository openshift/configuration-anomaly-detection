#!/bin/bash
set -euo pipefail

# clone
git -C backplane-api pull || git clone --depth 1 --branch master git@gitlab.cee.redhat.com:service/backplane-api.git
# build
cd backplane-api
make build
# setup, this does not look to good :D
sudo make dev-certs
sudo chmod 644 localhost.key
# setup ocm config
cp $HOME/.config/ocm/ocm.json configs/ocm.json
# run, in background? second terminal ?
RUN_ARGS=--cloud-config=./configs/cloud-config.yml make run-local-with-testremediation GIT_REPO="../"


