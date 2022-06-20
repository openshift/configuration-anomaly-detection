#!/usr/bin/env bash

if [[ -z "${SECRET_TOKEN}" ]]; then
  echo "SECRET_TOKEN environment variable not set"
  exit 1
fi

echo "[+] initializing load test"
echi "[+] each dot is an independent call of our API"
echo -n "[+] "
for i in $(seq 1 100); do
  echo -n "."
  curl -s -X POST -H "X-Secret-Token: ${SECRET_TOKEN}" --connect-timeout 1 --data @payload.json "https://configuration-anomaly-detection.stage.devshift.net/"
  sleep 2s
done
echo " done"