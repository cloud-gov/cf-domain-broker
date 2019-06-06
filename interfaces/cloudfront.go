package interfaces

import (
	"github.com/18f/cf-domain-broker/types"
	"github.com/aws/aws-sdk-go/service/cloudfront"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . CloudfrontDistribution
type CloudfrontDistribution interface {
	Create(callerReference string, domains []string, origin, path string, insecureOrigin bool, forwardedHeaders types.Headers, forwardCookies bool, tags map[string]string) (*cloudfront.Distribution, error)
	Update(distId string, domains []string, origin, path string, insecureOrigin bool, forwardedHeaders types.Headers, forwardCookies bool) (*cloudfront.Distribution, error)
	Get(distId string) (*cloudfront.Distribution, error)
	SetCertificate(distId, certId string) error
	SetCertificateAndCname(distId, certId string, domains []string) error
	Disable(distId string) error
	Delete(distId string) (bool, error)
	ListDistributions(callback func(cloudfront.DistributionSummary) bool) error
}
