package managers

import (
	"github.com/18f/cf-domain-broker/types"
	"github.com/jinzhu/gorm"
)

// DomainRouteModel is a single response type for both custom domains and CDN domains.
type DomainRouteModel struct {
	gorm.Model
	// The instance id of the Service in CF.
	InstanceId string `gorm:"not null;unique_index;primary_key"`

	// The DNS challenge data.
	DNSChallenge DomainMessenger

	// The ELB the route is tied to.
	ElbArn string

	// The IAM resource.
	IamCertificateArn string

	// The listener the certificate is tied to.
	ElbListenerArn string

	// DomainExternal is a slice of Domains because lots of DBs don't like array types.
	DomainExternal []types.Domain
	DomainInternal string

	// Cloudfront Distribution UserId.
	DistributionId string
	Origin         string
	Path           string
	InsecureOrigin bool
	ALBProxyARN    string
}

func (route *DomainRouteModel) GetDomains() []string {
	var domains []string
	for _, domain := range route.DomainExternal {
		domains = append(domains, domain.Value)
	}
	return domains
}
