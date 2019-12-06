#!/bin/bash

print_usage() {
  echo " "
  echo usage: $0 domain contact-email base-directory origin-domain origin-path
  echo " "
  echo "  domain: The custom domain you are creating certificates and the CDN for (example: cloud.example.com)."
  echo "  contact-email: The email address shared with Let's Encrypt for the domain (example: operator@cloud.gov). This can be your email."
  echo "  base-directory: Path to the base directory described above (example: ~/)."
  echo "  origin-domain: The domain cloudfront will use at the origin. This is frequently a Federalist site (and will be provided by the Federalist team) or an app on the app.cloud.gov domain."
  echo "  origin-path (optional): The path cloudfront will access on the origin-domain to fetch content (frequently provided by federalist team). If the origin is an app.cloud.gov app, there may not be an origin-path."
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
origin_domain=$4
origin_path=$5

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
  --logs-dir $base_directory/l$domain/ogs \
  --work-dir $base_directory/$domain/work \
  --manual --preferred-challenges dns-01 certonly

tf_vars="${base_directory}/${domain}/${domain}.tfvars"  
certs_dir="${base_directory}/${domain}/config/live/${domain}"

echo private_key_pem = "\"${certs_dir}/privkey.pem"\" > $tf_vars
echo cert_pem = "\"${certs_dir}/cert.pem"\" >> $tf_vars
echo chain_pem = "\"${certs_dir}/chain.pem"\" >> $tf_vars

echo custom_domain = "\"${domain}"\" >> $tf_vars
echo origin_id = "\"Custom-${domain}"\" >> $tf_vars
echo origin_domain = "\"${origin_domain}"\" >> $tf_vars

if [ ! -z "$origin_path" ]; then
  echo origin_path = "\"${origin_path}"\" >> $tf_vars
fi 

terraform apply --var-file $tf_vars