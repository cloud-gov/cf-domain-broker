## Custom Domain Broker

This is an Open Service Broker API-compliant custom domain broker for AWS
Elastic Load Balancing, designed primarily for Cloud Foundry.

> **Warning:** This is nearly production ready, but still has a long way to go
> on features.

### Broker Configuration

The Broker can be configured via the following environment variables:

`AWS_ACCESS_KEY_ID`            | AWS access key
`AWS_SECRET_ACCESS_KEY`        | AWS secret access key
`AWS_DEFAULT_REGION`           | AWS region to use
`ACME_ROOT`                    | _todo (mxplusb):_ this needs to go in acceptance_tests
`ACME_URL`                     | ACME server url, self-hosted, LE staging, or LE prod works.
`ALB_NAMES`                    | The resource names of the ELBs/ALBs you want to use for brokering custom domains. format: `alb-0,alb-1,`
`BROKER_NAME`                  | The name of the cf app which gets deployed.
`BUCKET`                       | The S3 bucket which will be used for HTTP-01 renewals.
`DATABASE_URL`                 | The Postgres database URL.
`DELETE_TEST_SERVICE_INSTANCE` | _todo (mxplusb):_ this needs to go in acceptance-tests
`EMAIL`                        | The registration email used to register new domain names.
`IAM_PATH_PREFIX`              | The IAM namespace to use.
`LOG_LEVEL`                    | _todo (mxplusb):_ make sure this actually does the thing
`PASS`                         | _todo (mxplusb):_ I think this is the broker password, need to document better
`RESOLVERS`                    | DNS pre-check resolvers, see more below
`SERVICE_OFFERINGS`            | _todo (mxplusb):_ figure out what this means
`URL`                          | _todo (mxplusb):_ this too
`USER`                         | _todo (mxplusb):_ I think this is the cf broker username

#### DNS Resolvers

Because the broker uses an [integration ACME tool called
Gravel](https://github.com/18f/gravel), the internal ACME client leverages a
custom DNS resolver precheck. This means the internal ACME client will try to
resolve TXT records from DNS-01 challenges before informing the upstream ACME
server the record is ready to be resolved. As part of that, if no resolvers are
set, no DNS-01 records will be able to be created as nothing will resolve (and
the broker will likely crash). The resolvers (can be more than one) must be in
the following format per resolver: `{Name}={IP}:{Port}`. For example:
`level3=4.2.2.2:53,google=8.8.8.8:53,cloudflare=1.1.1.1:53,internal-dns-server-for-internal-acme-server=192.168.0.2:53`.

### IAM Policies

As this broker manages ELBs, IAM Certificates, CloudFront and other
AWS resources, it requires an IAM policy that allows access to those APIs.
We've included a sample policy in `doc/sample_iam_policy.json`, but you're
responsible for auditing your own security policies. No warranty, etc, etc.

### Pipeline Configuration

This broker leverages [Concourse](https://concourse-ci.org) for it's deployment
automation, but it's not dependent on it.  You can find example and live
concourse configuration files in the `ci/` directory.

It's important to note this broker and it's configuration was designed first
and foremost for AWS GovCloud, which has some limitations when it comes to
global configurations. For example, Route53 is not avaialble in GovCloud as
it's a global service, so while the domain broker can be deployed as a Cloud
Foundry app in GovCloud, it still needs to cross the boundary into the AWS
commercial cloud.

_NB: Is the above still the case?_
