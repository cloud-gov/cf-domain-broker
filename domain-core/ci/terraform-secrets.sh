#!/bin/bash

bosh interpolate \
  broker-src/bosh/terraform.yml \
  -l terraform-yaml/state.yml \
  > terraform-secrets/terraform.yml
