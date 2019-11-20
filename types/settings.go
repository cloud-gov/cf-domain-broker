package types

import (
	"net/http"
	"strings"

	"code.cloudfoundry.org/lager"
	"github.com/aws/aws-sdk-go/service/cloudfront/cloudfrontiface"
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

	// AWS IAM.
	IamSvc iamiface.IAMAPI

	// AWS CloudFront.
	CloudFront cloudfrontiface.CloudFrontAPI

	// AWS ELBv2
	ElbSvc elbv2iface.ELBV2API

	// dns challenger
	PersistentDnsProvider bool
	DnsChallengeProvider  challenge.Provider

	// ACME Client, used mostly for testing.
	AcmeHttpClient *http.Client

	// DNS Resolvers
	Resolvers Resolver
}

type Resolver map[string]string

func (r *Resolver) Decode(value string) error {
	*r = make(map[string]string)
	s := strings.Split(value, ",")
	for idx := range s {
		ns := strings.Split(s[idx], "=")
		(*r)[ns[0]] = ns[1]
	}
	return nil
}
