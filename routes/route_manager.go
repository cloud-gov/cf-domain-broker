package routes

import (
	"code.cloudfoundry.org/lager"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/types"
	"github.com/aws/aws-sdk-go/service/elbv2/elbv2iface"
	"github.com/jinzhu/gorm"
)

type RouteManager struct {
	// todo (mxplusb): fix the AWS service weirdness

	Logger     lager.Logger
	Iam        types.IAM
	CloudFront types.CloudfrontDistribution
	Settings   types.Settings
	Db         *gorm.DB
	ElbSvc     elbv2iface.ELBV2API
}

func (*RouteManager) Create(instanceId string, domainOpts types.DomainPlanOptions, cdnOpts types.CdnPlanOptions, tags map[string]string) (*models.DomainRoute, error) {
	panic("implement me")
}

func (*RouteManager) Update(instanceId string, domainOpts types.DomainPlanOptions, cdnOpts types.CdnPlanOptions) error {
	panic("implement me")
}

func (*RouteManager) Get(instanceId string) (*models.DomainRoute, error) {
	panic("implement me")
}

func (*RouteManager) Poll(route *models.DomainRoute) error {
	panic("implement me")
}

func (*RouteManager) Disable(route *models.DomainRoute) error {
	panic("implement me")
}

func (*RouteManager) Renew(route *models.DomainRoute) error {
	panic("implement me")
}

func (*RouteManager) RenewAll() {
	panic("implement me")
}

func (*RouteManager) DeleteOrphanedCerts() {
	panic("implement me")
}

func (*RouteManager) GetDNSInstructions(route *models.DomainRoute) ([]string, error) {
	panic("implement me")
}

func (*RouteManager) Populate() error {
	panic("implement me")
}

func NewManager(logger lager.Logger, iam types.IAM, cloudFront types.CloudfrontDistribution, elbSvc elbv2iface.ELBV2API, settings types.Settings, db *gorm.DB) RouteManager {
	return RouteManager{
		Logger:     logger,
		Iam:        iam,
		CloudFront: cloudFront,
		Settings:   settings,
		Db:         db,
		ElbSvc:     elbSvc,
	}
}
