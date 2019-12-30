#!/bin/bash

print_usage() {
  echo " "
  echo usage: $0 domain contact-email base-directory listener-arn
  echo " "
  echo "  domain: The custom domain you are creating certificates and the CDN for (example: cloud.example.com)."
  echo "  contact-email: The email address shared with Let's Encrypt for the domain (example: operator@cloud.gov). This can be your email."
  echo "  base-directory: Path to the base directory described above (example: ~/)."
  echo "  listener-arn: The ARN of the load balancer's https listener to add the cert to."
  echo " "
}

if [ "$1" == "" ] || [ "$2" = "" ] || [ "$3" = "" ] || [ "$4" = "" ]; then
  print_usage
  exit
fi

this_directory=$(dirname "$0")
domain=$1
contact_email=$2
base_directory=$3
listener_arn=$4


if [ ! -d $base_directory ]; then
  echo " "
  echo "ERROR: base-directory does not exist: ${base_directory}"
  print_usage
  exit
fi

set -e

mkdir -p $base_directory/$domain/config
mkdir -p $base_directory/$domain/logs
mkdir -p $base_directory/$domain/work

certbot \
  -m $contact_email \
  --agree-tos --eff-email \
  --domain $domain \
  --config-dir $base_directory/$domain/config \
  --logs-dir $base_directory/$domain/logs \
  --work-dir $base_directory/$domain/work \
  --manual --preferred-challenges dns-01 certonly

tf_vars="${base_directory}/${domain}/${domain}.tfvars"  
certs_dir="${base_directory}/${domain}/config/live/${domain}"

echo private_key_pem = "\"${certs_dir}/privkey.pem"\" > $tf_vars
echo cert_pem = "\"${certs_dir}/cert.pem"\" >> $tf_vars
echo chain_pem = "\"${certs_dir}/chain.pem"\" >> $tf_vars

echo custom_domain = "\"${domain}"\" >> $tf_vars
echo listener_arn = "\"${listener_arn}"\" >> $tf_vars

terraform apply --var-file $tf_vars