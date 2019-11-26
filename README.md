## Custom Domain Broker

This is an Open Service Broker API-compliant custom domain broker for AWS Elastic Load Balancing, designed primarily for Cloud Foundry.

:warn: This is nearly production ready, but still has a long way to go on features.

### Broker Configuration

This configuration section is primarily designed for broker operations. Each of these configuration options (minus acceptance tests) can be set as environment variables within the runtime environment, either in Cloud Foundry or outside of it.

```yaml
access-key-id: # aws access key
acme-root: # todo (mxplusb): this needs to go in acceptance-tests
acme-url: # acme server url, self-hosted, LE staging, or LE prod works.
alb-names: # the resource names of the ELBs/ALBs you want to use for brokering custom domains. format: alb-0,alb-1,
broker-name: # the name of the cf app which gets deployed.
bucket: # the S3 bucket which will be used for HTTP-01 renewals.
database-url: # the postgres database URL.
delete-test-service-instance: # todo (mxplusb): this needs to go in acceptance-tests
email: # the registration email used to register new domain names.
iam-path-prefix: # the IAM namespace to use.
log-level: # todo (mxplusb): make sure this actually does the thing
pass: # todo (mxplusb): I think this is the broker password, need to document better
region: # aws region to use
resolvers: # dns pre-check resolvers, see more below
secret-access-key-id: # aws secret access key
service-offerings: # todo (mxplusb): figure out what this means
url: # todo (mxplusb): this too
user: # todo (mxplusb): I think this is the cf broker username
```

#### DNS Resolvers

Because the broker uses an [integration ACME tool called Gravel](https://github.com/18f/gravel), the internal ACME client leverages a custom DNS resolver precheck. This means the internal ACME client will try to resolve TXT records from DNS-01 challenges before informing the upstream ACME server the record is ready to be resolved. As part of that, if no resolvers are set, no DNS-01 records will be able to be created as nothing will resolve (and the broker will likely crash). The resolvers (can be more than one) must be in the following format per resolver: `{Name}={IP}:{Port}`. For example: `level3=4.2.2.2:53,google=8.8.8.8:53,cloudflare=1.1.1.1:53,internal-dns-server-for-internal-acme-server=192.168.0.2:53`.

### IAM Policies

While the specific policies needed for this broker don't live here, this is a good starting point.

```json
{
	"Version": "2012-10-17",
	"Statement": [{
			"Action": [
				"elasticloadbalancing:CreateLoadBalancer",
				"elasticloadbalancing:DeleteLoadBalancer"
			],
			"Effect": "Deny",
			"Resource": "*"
		},
		{
			"Action": [
				"elasticloadbalancing:AddListenerCertificates",
				"elasticloadbalancing:CreateListener",
				"elasticloadbalancing:CreateRule",
				"elasticloadbalancing:CreateLoadBalancerListeners",
				"elasticloadbalancing:CreateTargetGroup",
				"elasticloadbalancing:DeleteListener",
				"elasticloadbalancing:DeleteRule",
				"elasticloadbalancing:DeleteTargetGroup",
				"elasticloadbalancing:DeregisterTargets",
				"elasticloadbalancing:Describe*",
				"elasticloadbalancing:Modify*",
				"elasticloadbalancing:RegisterTargets",
				"elasticloadbalancing:RemoveListenerCertificates"
			],
			"Effect": "Allow",
			"Resource": "*"
		},
		{
			"Action": [
				"iam:DeleteServerCertificate",
				"iam:GetServerCertificate",
				"iam:ListServerCertificates",
				"iam:UpdateServerCertificate",
				"iam:UploadServerCertificate"
			],
			"Effect": "Allow",
			"Resource": "*"
		},
		{
			"Effect": "Allow",
			"Action": [
				"iam:DeleteServerCertificate",
				"iam:ListServerCertificates",
				"iam:UploadServerCertificate",
				"iam:UpdateServerCertificate"
			],
			"Resource": [
				"arn:${aws_partition}:iam::${account_id}:server-certificate/cloudfront/${cloudfront_prefix}"
			]
		},
		{
			"Effect": "Allow",
			"Action": "cloudfront:*",
			"Resource": "*"
		},
		{
			"Effect": "Allow",
			"Action": [
				"s3:GetObject",
				"s3:PutObject",
				"s3:DeleteObject"
			],
			"Resource": [
				"arn:${aws_partition}:s3:::${bucket}/*"
			]
		},
		{
			"Effect": "Allow",
			"Action": [
				"route53:ChangeResourceRecordSets"
			],
			"Resource": [
				"arn:${aws_partition}:route53:::hostedzone/${hosted_zone}"
			]
		}
	]
}
```

### Pipeline Configuration

This broker leverages [Concourse](https://concourse-ci.org) for it's deployment automation, but it's not dependent on it. It's important to note this broker and it's configuration was designed first and foremost for AWS GovCloud, which has some limitations when it comes to global configurations. For example, Route53 is not avaialble in GovCloud as it's a global service, so while the domain broker can be deployed as a Cloud Foundry app in GovCloud, it still needs to cross the boundary into the AWS commercial cloud.

```yaml
domain-broker-v2-service-offerings:
pipeline-tasks-git-branch:
pipeline-tasks-git-url:

slack:
  channel:
  icon-url:
  username:
  webhook-url:

cf:
  $env:
    api:
    user:
    password:
    org:
    space:

aws:
  plan-name:
  commercial:
    access-key-id:
    secret-access-key:
    hosted-zone-id:

domain-broker-v2:
  source:
    git-remote:
    git-branch:
  $env:
    access-key-id:
    acme-root:
    acme-url:
    alb-names:
    broker-name:
    bucket:
    database-url:
    delete-test-service-instance:
    email:
    iam-path-prefix:
    log-level:
    pass:
    region:
    resolvers:
    secret-access-key-id:
    service-offerings:
    url:
    user:
    acceptance-tests:
      plan-name:
      test-domain:
      service-instance-name:
```