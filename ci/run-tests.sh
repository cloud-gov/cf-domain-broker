#!/bin/bash

set -eux

pushd cf-domain-broker
  go get -v -u ./...
  go test -v ./...
popd
