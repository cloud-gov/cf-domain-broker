package interfaces

import (
	le_providers "github.com/18f/cf-domain-broker/le-providers"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/types"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . RouteManager
type RouteManager interface {
	Create(instanceId string, domainOpts types.DomainPlanOptions, cdnOpts types.CdnPlanOptions, tags map[string]string) (*models.DomainRoute, error)
	Update(instanceId string, domainOpts types.DomainPlanOptions, cdnOpts types.CdnPlanOptions) error
	Get(instanceId string) (models.DomainRoute, error)
	Poll(route *models.DomainRoute) error
	Disable(route *models.DomainRoute) error
	Renew(route *models.DomainRoute) error
	RenewAll()
	DeleteOrphanedCerts()
	GetDNSInstructions(route *models.DomainRoute) (le_providers.DomainMessenger, error)
	Populate() error
}
