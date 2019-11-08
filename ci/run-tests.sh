#!/bin/bash

set -eux

export GOPATH=$(pwd)/gopath

pushd gopath/src/github.com/18F/cf-domain-broker
  go get -v -u ./...
  go test -v
popd
