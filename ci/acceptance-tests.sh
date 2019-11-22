#!/bin/bash

set -eux

# Set defaults
TTL="${TTL:-60}"
DOMAINS_TIMEOUT="${DOMAINS_TIMEOUT:-7200}"

suffix="$(cat /proc/sys/kernel/random/uuid | cut -c1-4)"
DOMAIN=$(printf "${DOMAIN}" "${suffix}")
SERVICE_INSTANCE_NAME=$(printf "${SERVICE_INSTANCE_NAME}" "${suffix}")

# allow setting a CA_CERT_URL for testing against Let's Encrypt's staging environment
curl_args=""
if [ -n "${CA_CERT_URL:-}" ]; then
  curl -o ca.pem "${CA_CERT_URL}"
  curl_args="--cacert ca.pem"
fi

path="$(dirname $0)"

# Authenticate
cf api "${CF_API_URL}"
(
  set +x
  cf auth "${CF_USERNAME}" "${CF_PASSWORD}"
)

# Target
cf target -o "${CF_ORGANIZATION}" -s "${CF_SPACE}"

# Create private domain
cf create-domain "${CF_ORGANIZATION}" "${DOMAIN}"

# the create service below intermittently runs too quickly
# and fails because it can't yet find the domian.
sleep 5

# Create service
opts=$(jq -n --arg domains "${DOMAIN}" '{domains: [$domains]}')
cf create-service -b "${BROKER_NAME}" "${SERVICE_NAME}" "${PLAN_NAME}" "${SERVICE_INSTANCE_NAME}" -c "${opts}"
service_guid=$(cf service "${SERVICE_INSTANCE_NAME}" --guid)

elapsed=300
until [ "${elapsed}" -le 0 ]; do
  status=$(cf curl "/v2/service_instances/${service_guid}")
  description=$(echo "${status}" | jq -r '.entity.last_operation.description | fromjson')
  domain_external=$(echo "${description}" | jq -r '.[].domain')
  alb_domain=$(echo "${description}" | jq -r '.[].cname')
  txt_name=$(echo "${description}" | jq -r '.[].txt_record')
  txt_value=$(echo "${description}" | jq -r '.[].txt_value')
  txt_ttl=$(echo "${description}" | jq -r '.[].ttl')
  if [ -n "${alb_domain:-}" ] && [ -n "${txt_name:-}" ]; then
    break
  fi
  let elapsed-=5
  sleep 5
done
if [ -z "${alb_domain:-}" ] || [ -z "${txt_name:-}" ]; then
  echo "Failed to parse description: ${description}"
  exit 1
fi

# Create DNS record(s)
cat <<EOF >./create-cname.json
{
  "Changes": [
    {
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "${domain_external}.",
        "Type": "CNAME",
        "TTL": ${TTL},
        "ResourceRecords": [
          {"Value": "${domain_internal}"}
        ]
      }
    }
  ]
}
EOF

if [ "${CHALLENGE_TYPE}" = "DNS-01" ]; then
  cat <<EOF >./create-txt.json
{
  "Changes": [
    {
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "${txt_name}",
        "Type": "TXT",
        "TTL": ${txt_ttl},
        "ResourceRecords": [
          {"Value": "\"${txt_value}\""}
        ]
      }
    }
  ]
}
EOF
fi

if [ "${CHALLENGE_TYPE}" = "HTTP-01" ]; then
  aws route53 change-resource-record-sets \
    --hosted-zone-id "${HOSTED_ZONE_ID}" \
    --change-batch file://./create-cname.json
elif [ "${CHALLENGE_TYPE}" = "DNS-01" ]; then
  aws route53 change-resource-record-sets \
    --hosted-zone-id "${HOSTED_ZONE_ID}" \
    --change-batch file://./create-txt.json
fi

# Wait for provision to complete
elapsed="${DOMAINS_TIMEOUT}"
until [ "${elapsed}" -le 0 ]; do
  status=$(cf curl "/v2/service_instances/${service_guid}")
  state=$(echo "${status}" | jq -r '.entity.last_operation.state')
  if [[ "${state}" == "succeeded" ]]; then
    updated="true"
    break
  elif [[ "${state}" == "failed" ]]; then
    echo "Failed to create service"
    exit 1
  fi
  let elapsed-=60
  sleep 60
done
if [ "${updated}" != "true" ]; then
  echo "Failed to update service ${SERVICE_NAME}"
  exit 1
fi

# Create CNAME after provisioning if using DNS-01 challenge
if [ "${CHALLENGE_TYPE}" = "DNS-01" ]; then
  aws route53 change-resource-record-sets \
    --hosted-zone-id "${HOSTED_ZONE_ID}" \
    --change-batch file://./create-cname.json
fi

# Push test app
cat <<EOF >"${path}/app/manifest.yml"
---
applications:
- name: domain-broker-test-${CHALLENGE_TYPE}
  buildpack: staticfile_buildpack
  domain: ${DOMAIN}
  no-hostname: true
EOF

cf push -f "${path}/app/manifest.yml" -p "${path}/app"

# Assert expected response from domain
elapsed="${DOMAINS_TIMEOUT}"
until [ "${elapsed}" -le 0 ]; do
  if curl ${curl_args} "https://${DOMAIN}" | grep "Domain Broker Test"; then
    break
  fi
  let elapsed-=60
  sleep 60
done
if [ -z "${elapsed}" ]; then
  echo "Failed to load ${DOMAIN}"
  exit 1
fi

if [ "${DELETE_SERVICE:-"true"}" == "true" ]; then
  # Delete private domain
  cf delete-domain -f "${DOMAIN}"

  # Delete DNS record(s)
  cat <<EOF >./delete-cname.json
{
  "Changes": [
    {
      "Action": "DELETE",
      "ResourceRecordSet": {
        "Name": "${domain_external}.",
        "Type": "CNAME",
        "TTL": ${TTL},
        "ResourceRecords": [
          {"Value": "${domain_internal}"}
        ]
      }
    }
  ]
}
EOF
  if [ "${CHALLENGE_TYPE}" = "DNS-01" ]; then
    cat <<EOF >./delete-txt.json
{
  "Changes": [
    {
      "Action": "DELETE",
      "ResourceRecordSet": {
        "Name": "${txt_name}.",
        "Type": "TXT",
        "TTL": ${txt_ttl},
        "ResourceRecords": [
          {"Value": "${txt_value}"}
        ]
      }
    }
  ]
}
EOF

    aws route53 change-resource-record-sets \
      --hosted-zone-id "${HOSTED_ZONE_ID}" \
      --change-batch file://./delete-cname.json
  elif [ "${CHALLENGE_TYPE}" = "DNS-01" ]; then
    aws route53 change-resource-record-sets \
      --hosted-zone-id "${HOSTED_ZONE_ID}" \
      --change-batch file://./delete-txt.json
  fi

  # Delete service
  cf delete-service -f "${SERVICE_INSTANCE_NAME}"

  # Wait for deprovision to complete
  elapsed="${DOMAINS_TIMEOUT}"
  until [ "${elapsed}" -le 0 ]; do
    if ! cf service "${SERVICE_INSTANCE_NAME}"; then
      deleted="true"
      break
    fi
    let elapsed-=60
    sleep 60
  done
  if [ "${deleted}" != "true" ]; then
    echo "Failed to delete service ${SERVICE_NAME}"
    exit 1
  fi
fi
