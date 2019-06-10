package models

import (
	cf_domain_broker "github.com/18f/cf-domain-broker"
	le_providers "github.com/18f/cf-domain-broker/le-providers"
	"github.com/go-acme/lego/certificate"
	"github.com/jinzhu/gorm"
)

// DomainRoute is a single response type for both custom domains and CDN domains.
type DomainRoute struct {
	gorm.Model
	// The instance id of the Service in CF.
	InstanceId string `gorm:"not null;unique_index;primary_key"`

	// Instance status
	State cf_domain_broker.State

	// Our user data.
	User UserData `gorm:"not null" gorm:"foreignkey:UserRef"`

	// The DNS challenge data.
	DNSChallenge le_providers.DomainMessenger

	// Our certificate.
	Certificate *certificate.Resource `gorm:"foreignkey:CertRef"`

	// The ELB the route is tied to.
	ELBArn string

	// The listener the certificate is tied to.
	ListenerArn string

	DomainExternal string
	DomainInternal string

	// Cloudfront Distribution Id.
	DistributionId string
	Origin         string
	Path           string
	InsecureOrigin bool
	ALBProxyARN    string
}
