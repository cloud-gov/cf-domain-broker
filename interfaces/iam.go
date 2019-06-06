package interfaces

import (
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/jmcarp/lego/acme"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . IamCertificateManager
type IamCertificateManager interface {
	UploadCertificate(name string, cert acme.CertificateResource) (string, error)
	DeleteCertificate(name string) error
	ListCertificates(callback func(iam.ServerCertificateMetadata) bool) error
}
