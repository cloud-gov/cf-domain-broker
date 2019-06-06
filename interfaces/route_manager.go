package interfaces

import (
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/types"
)

type RouteManager interface {
	Create(instanceId, domain, origin, path string, insecureOrigin bool, forwardedHeaders types.Headers, forwardCookies bool, tags map[string]string) (*models.Route, error)
	Update(instanceId string, domain, origin string, path string, insecureOrigin bool, forwardedHeaders types.Headers, forwardCookies bool) error
	Get(instanceId string) (*models.Route, error)
	Poll(route *models.Route) error
	Disable(route *models.Route) error
	Renew(route *models.Route) error
	RenewAll()
	DeleteOrphanedCerts()
	GetDNSInstructions(route *models.Route) ([]string, error)
	Populate() error
}
