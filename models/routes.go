package models

import (
	cfdomainbroker "github.com/18f/cf-domain-broker"
	leproviders "github.com/18f/cf-domain-broker/le-providers"
	"github.com/jinzhu/gorm"
)

// DomainRoute is a single response type for both custom domains and CDN domains.
type DomainRoute struct {
	gorm.Model
	// The instance id of the Service in CF.
	InstanceId string `gorm:"not null;unique_index;primary_key"`

	// Instance status
	State cfdomainbroker.State

	// Our user data.
	User UserData `gorm:"not null" gorm:"foreignkey:UserRef"`

	// The DNS challenge data.
	DNSChallenge leproviders.DomainMessenger

	// Our certificate.
	Certificate *Certificate `gorm:"foreignkey:CertRef"`

	// The ELB the route is tied to.
	ELBArn string

	// The listener the certificate is tied to.
	ListenerArn string

	// DomainExternal is a slice of Domains because lots of DBs don't like array types.
	DomainExternal []Domain `gorm:"foreignkey:domains"`
	DomainInternal string

	// Cloudfront Distribution UserId.
	DistributionId string
	Origin         string
	Path           string
	InsecureOrigin bool
	ALBProxyARN    string
}

// Domain is an instance of a domain.
type Domain struct {
	gorm.Model
	Value string
}

func (route *DomainRoute) GetDomains() []string {
	var domains []string
	for _, domain := range route.DomainExternal {
		domains = append(domains, domain.Value)
	}
	return domains
}

/*
func (route *DomainRoute) LoadUser(db *gorm.DB) (UserData, error) {
	var userData UserData
	if err := db.Model(route).Related(&userData).Error; err != nil {
		return UserData{}, err
	}

	return
}*/
