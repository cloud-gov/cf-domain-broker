package interfaces

import (
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/go-acme/lego/v3/certificate"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . IamCertificateManager
type IamCertificateManager interface {
	UploadCertificate(name string, resource certificate.Resource) (string, error)
	DeleteCertificate(name string) error
	ListCertificates(callback func(iam.ServerCertificateMetadata) bool) error
}
