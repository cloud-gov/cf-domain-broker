package cf_domain_broker

import "time"

const (
	DomainServiceName = "custom-domain-broker"
	DomainServiceId   = "7428b169-f693-46c8-86bc-6dc8a8ea1361"

	// todo (mxplusb): update this.
	DomainServiceDescription                 = "Service Broker description to go here."
	DomainServiceMetadataDisplayName         = "display"
	DomainServiceMetadataLongDescription     = "long"
	DomainServiceMetadataDocumentationUrl    = "https://google.com"
	DomainServiceMetadataSupportUrl          = "https://cloud.gov/support"
	DomainServiceMetadataImageUrl            = "some-image"
	DomainServiceMetadataProviderDisplayName = "something"

	CDNPlanName = "domain-with-cdn-and-ssl"
	CDNPlanId   = "a0bc63d1-cd2a-44e5-a709-396b382676f0"

	DomainPlanName = "domain-with-ssl"
	DomainPlanId   = "5d4bcdef-efa1-4b0a-b658-7776c3438e4a"

	MaxHeaderCount = 10

	DomainCreateTimeout = time.Hour * 24
	DomainCreateCheck   = time.Second * 10

	Provisioning   State = 0
	Provisioned    State = 1
	Deprovisioning State = 2
	Deprovisioned  State = 3
)

type State int
