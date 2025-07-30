#!/usr/bin/env bash
set -euo pipefail

#assuming we're launched from inside the configuration-anomaly-detection repository
CAD_REPO_PATH=$(git rev-parse --show-toplevel)
echo "Assuming CAD repository root is ${CAD_REPO_PATH}"

#check presence of binary, assume the dnf package name is the same
check_presence () {
    # $1 - name of the binary
    echo -n "Checking presence of $1..."
    if ! which $1 2>/dev/null >/dev/null; then
        echo "Not Found"
        echo "Try 'dnf install $1' on Fedora"
        exit -1
    else
        echo "Found"
    fi
}

# clean up child processes on SIGINT
trap "kill -- -$$" EXIT

check_presence "jq"
check_presence "openssl"
check_presence "tinyproxy"
check_presence "haproxy"
check_presence "proxytunnel"

#loading env vars
. ${CAD_REPO_PATH}/test/set_stage_env.sh

#checking env vars
set +u
if [[ -z "${OCM_BACKPLANE_REPO_PATH}" ]]; then
    echo "Please set OCM_BACKPLANE_REPO_PATH variable to the path of the OCM Backplane code repository"
    exit -1
fi
set -u

if ! [ "$(cat ${OCM_BACKPLANE_REPO_PATH}/configs/ocm.json | jq -r .client_id)" = "ocm-backplane-staging" ]; then
    echo "OCM Backplane ocm.json (${OCM_BACKPLANE_REPO_PATH}/configs/ocm.json) isn't the ocm-backplane-staging config."
    echo "Please get the config from a backplane pod on a staging backplanes0* cluster (in /ocm inside the pod)"
    echo "and place it in the configs subdirectory of the backplane-api repo."
    exit -1
fi

#checking certificate validity
if ! openssl verify ${OCM_BACKPLANE_REPO_PATH}/localhost.crt; then
    echo "Certificate ${OCM_BACKPLANE_REPO_PATH}/localhost.crt not valid, please run make dev-certs in the OCM Backplane directory as root to generate and trust the localhost certificates"
    exit -1
fi

#creating certificate file for the HAProxy
cat ${OCM_BACKPLANE_REPO_PATH}/localhost.crt ${OCM_BACKPLANE_REPO_PATH}/localhost.key > ${CAD_REPO_PATH}/test/testinfra/localhost.pem

#checking BACKPLANE_PROXY reachability reachability
echo "Checking Proxy reachability"
if ! curl ${BACKPLANE_PROXY} -o /dev/null; then
    echo "Proxy ${BACKPLANE_PROXY} not reachable, check VPN connection"
    exit -1
fi

#run the env
echo "Starting tinyproxy on port 8888"
tinyproxy -d -c ${CAD_REPO_PATH}/test/testinfra/tinyproxy.conf > ${CAD_REPO_PATH}/test/testinfra/tinyproxy.log 2> ${CAD_REPO_PATH}/test/testinfra/tinyproxy.error.log&

echo "Starting proxytunnel on port 8091"
proxytunnel -v -p squid.corp.redhat.com:3128 -d api.stage.backplane.openshift.com:443 -a 8091 > ${CAD_REPO_PATH}/test/testinfra/proxytunnel.log 2> ${CAD_REPO_PATH}/test/testinfra/proxytunnel.error.log &

echo "Starting haproxy on port 8443"
pushd ${CAD_REPO_PATH}/test/testinfra/
haproxy -f haproxy.cfg > ${CAD_REPO_PATH}/test/testinfra/haproxy.log 2> ${CAD_REPO_PATH}/test/testinfra/haproxy.error.log &
popd

echo "Starting backplane-api on port 8001"
pushd $OCM_BACKPLANE_REPO_PATH
GIT_REPO=${CAD_REPO_PATH} make run-local-with-testremediation > ${CAD_REPO_PATH}/test/testinfra/backplan-api.log 2> ${CAD_REPO_PATH}/test/testinfra/backplan-api.error.log &
popd

echo "Environment started. Check ${CAD_REPO_PATH}/test/testinfra/ directory for logs"
echo "Run cadctl with the following command to test against the local backplane-api for remediations"
echo ""
echo "BACKPLANE_URL=https://localhost:8443 HTTP_PROXY=http://127.0.0.1:8888 HTTPS_PROXY=http://127.0.0.1:8888 BACKPLANE_PROXY=http://127.0.0.1:8888  ./bin/cadctl investigate --payload-path ./payload --log-level debug"
echo ""
echo "Send SIGINT (Ctrl+C) to terminate the local infrastructure"
#keep the script alive until all child processes are cleaned up
wait
