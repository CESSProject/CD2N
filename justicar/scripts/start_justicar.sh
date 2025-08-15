#!/usr/bin/env bash

set -e


WORK_DIR=$(dirname $(readlink -f "$0"))
DATA_DIR=${DATA_DIR:-"${WORK_DIR}/data"}

echo "Work dir '${WORK_DIR}'"
echo "Data dir '${DATA_DIR}'"

GRAMINE_SGX_BIN=${GRAMINE_SGX_BIN:-"${WORK_DIR}/gramine-sgx"}
GRAMINE_DIRECT_BIN=${GRAMINE_DIRECT_BIN:-"gramine-direct"}


echo "Starting CDN TEE with extra opts '${EXTRA_OPTS}'"
if [ "$SGX" -eq 0 ]; then
  echo "justicar running in software mode"
  cd $WORK_DIR && $GRAMINE_DIRECT_BIN justicar $EXTRA_OPTS
else
  echo "justicar running in hardware mode"
  cd $WORK_DIR && $GRAMINE_SGX_BIN justicar $EXTRA_OPTS
fi