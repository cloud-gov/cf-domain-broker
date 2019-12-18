# CloudFoundry Custom Domain Broker

This is an Open Service Broker API-compliant custom domain broker for AWS
Elastic Load Balancing, designed primarily for Cloud Foundry.

> **Warning:** This is nearly production ready, but still has a long way to go
> on features.

It's important to note this broker and it's configuration was designed first
and foremost for AWS GovCloud, which has some limitations when it comes to
global configurations. For example, Route53 is not avaialble in GovCloud as
it's a global service, so while the domain broker can be deployed as a Cloud
Foundry app in GovCloud, it still needs to cross the boundary into the AWS
commercial cloud.

_NB: Is the above still the case?_

*Note:* This README focuses on deployment and usage.  If you're a developer
working on the broker, you probably want to check out the [developer
documentation](/doc/development.md) as well.

## Usage

When users request a domain service instance, this broker will provision a
Let's Encrypt certificate, an ELB and a CloudFront CDN, and wire them all up
together.  It does _not_ attempt to manage DNS (as most users already have DNS
solutions in place).

This requires a manual step to be performed by the user after the instance is
created, as described...  here:

### Let's Encrypt Challenge Challenges

We have some constraints that make the [Let's Encrypt Challenge
process](https://letsencrypt.org/docs/challenge-types/) "difficult":

#### `HTTP01`

`HTTP01` with CloudFront gives us a chicken-and-egg problem, in that CloudFront
will not answer to a custom domain, even for HTTP, without [verifying ownership
of that domain via a valid SSL
certificate](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html#https-requirements-certificate-issuer):

> If you want to use an alternate domain name with your CloudFront
> distribution, you must verify to CloudFront that you have authorized rights
> to use the alternate domain name. To do this, you must attach a valid
> certificate to your distribution, and make sure that the certificate comes
> from a trusted CA that is listed on the Mozilla Included CA Certificate List.
> **CloudFront does not allow you to use a self-signed certificate to verify your
> authorized rights to use an alternate domain name.**

#### `TLS-ALPN01`

We still need to fully investigate `ALPN01`, and its support in CloudFront.
It's not clear if the `ALPN01` certificate is a self-signed cert - if so, we'll
likely hit the same CloudFront limitation listed above.

Investigation pointers:

* [CloudFront supports HTTP/2](https://aws.amazon.com/about-aws/whats-new/2016/09/amazon-cloudfront-now-supports-http2/)
* [ALPN is the required SSL implementation for HTTP/2](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation)
* [Dehydrate](https://github.com/lukas2511/dehydrated/blob/master/docs/tls-alpn.md) bash ACME client can generate ALPN certs.

#### `DNS01`

We do not have access to or control over DNS for the application, so we cannot
automate the `DNS01` challenge.

#### Our Solution - Manual DNS Updates

Because of these limitations, we return instructions to the end user as to how
to configure their DNS `TXT` record.  We then monitor DNS for the record to be
set and propagated globally before continuing with the `DNS01` challenge
verification.

## Broker Configuration

The Broker can be configured via the following environment variables:

Variable                       | Meaning
-------------------------------|------------------------------------------------------
`AWS_ACCESS_KEY_ID`            | AWS access key
`AWS_SECRET_ACCESS_KEY`        | AWS secret access key
`AWS_DEFAULT_REGION`           | AWS region to use
`ACME_ROOT`                    | _todo (mxplusb):_ this needs to go in acceptance_tests
`ACME_URL`                     | ACME server url, self-hosted, LE staging, or LE prod works.
`ALB_NAMES`                    | The resource names of the ELBs/ALBs you want to use for brokering custom domains. format: `alb-0,alb-1`
`BROKER_NAME`                  | The name of the cf app which gets deployed.
`BUCKET`                       | The S3 bucket which will be used for HTTP01 renewals.
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

> **Tip**: These map directly to the keys in [`RuntimeSettings`](/types/broker.go).

### `RESOLVERS`

The internal ACME client leverages a custom DNS resolver pre-check. This means
the internal ACME client will try to resolve `TXT` records from DNS01 challenges
before informing the upstream ACME server the record is ready to be resolved.

As part of that, if no resolvers are set, no DNS01 records will be able to be
created as nothing will resolve (and the broker will likely crash).

The resolvers (can be more than one) must be in the following format per resolver:
`{Name}={IP}:{Port}`. For example:

``` bash
RESOLVERS="level3=4.2.2.2:53,google=8.8.8.8:53,internal=192.168.0.2:53"
```

## IAM Policies

As this broker manages ELBs, IAM Certificates, CloudFront and other
AWS resources, it requires an IAM policy that allows access to those APIs.
We've [provided a sample policy](/doc/sample_iam_policy.json), but you're
responsible for auditing your own security policies. No warranty, etc, etc.

## Pipeline Configuration

This broker leverages [Concourse](https://concourse-ci.org) for it's deployment
automation, but it's not dependent on it.  You can find example and live
concourse configuration files in [the `ci/` directory](/ci).
