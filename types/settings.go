package types

import (
	"net/http"

	"code.cloudfoundry.org/lager"
	"github.com/18f/cf-domain-broker/interfaces"
	"github.com/18f/cf-domain-broker/routes"
	"github.com/aws/aws-sdk-go/service/elbv2/elbv2iface"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/jinzhu/gorm"
)

type GlobalSettings struct {
	// Internal database.
	Db *gorm.DB

	// Inherited from main.
	Logger lager.Logger

	// Global settings from the environment, only read on startup.
	RuntimeSettings RuntimeSettings

	// Worker Manager settings
	WorkerManagerOpts routes.WorkerManagerSettings

	// AWS IAM.
	IamSvc iamiface.IAMAPI

	// AWS CloudFront.
	CloudFront interfaces.CloudfrontDistributionIface

	// AWS ELBv2
	ElbSvc elbv2iface.ELBV2API

	// dns challenger
	PersistentDnsProvider bool
	DnsChallengeProvider  challenge.Provider

	// ACME Client, used mostly for testing.
	AcmeHttpClient *http.Client

	// DNS Resolvers
	Resolvers map[string]string
}
